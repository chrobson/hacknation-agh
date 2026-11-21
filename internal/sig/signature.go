package sig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/chrobson/hacknation-agh/internal/httpfp"
)

// Limits enforced by the validator.
const (
	MaxPaths     = 3  // distinct extra paths a signature may request
	MaxMatchers  = 12 // matchers per signature
	MaxYAMLBytes = 32 << 10
	maxPathLen   = 256
	maxHeaders   = 4
)

// Severities accepted in Signature.Severity and Outdated.Severity
// (DefectDojo levels, written in lower case in YAML).
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Categories accepted in Signature.Category.
var Categories = []string{"cms", "framework", "server", "iot", "admin-panel", "staging", "other"}

// Matcher types.
const (
	TypeHeader   = "header"
	TypeCookie   = "cookie"
	TypeTitle    = "title"
	TypeBody     = "body"
	TypeFavicon  = "favicon"
	TypeStatus   = "status"
	TypePath     = "path"
	TypeTLS      = "tls"
	TypeHostname = "hostname"
	TypeService  = "service"
)

// MatcherTypes lists every supported matcher type.
var MatcherTypes = []string{TypeHeader, TypeCookie, TypeTitle, TypeBody, TypeFavicon, TypeStatus, TypePath, TypeTLS, TypeHostname, TypeService}

// Signature is one detection rule loaded from YAML.
type Signature struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Category    string `yaml:"category"`
	Confidence  int    `yaml:"confidence"`
	Description string `yaml:"description,omitempty"`
	Condition   string `yaml:"condition,omitempty"` // or (default) | and
	// Severity overrides the category default in exports (info|low|medium|
	// high|critical), e.g. high for an unauthenticated management API.
	Severity string `yaml:"severity,omitempty"`
	// Outdated raises the severity when the detected version (a named
	// "version" regex group) is older than Below. With "or", matching goes
	// on after the first hit until some matcher yields a version.
	Outdated *OutdatedRule `yaml:"outdated,omitempty"`
	Matchers []MatcherSpec `yaml:"matchers"`

	// Raw is the source YAML (stored in the signatures table).
	Raw string `yaml:"-"`
}

// OutdatedRule flags versions older than Below (dotted numbers, e.g. "6.0").
type OutdatedRule struct {
	Below    string `yaml:"below"`
	Severity string `yaml:"severity"`
}

// MatcherSpec is one matcher. Which fields apply depends on Type.
type MatcherSpec struct {
	Type string `yaml:"type"`
	// Negate inverts a service, header, title or body matcher (e.g. "the
	// nmap extra info does not mention authentication"). A negated HTTP
	// matcher never matches a service without an HTTP response.
	Negate bool `yaml:"negate,omitempty"`
	// VersionOnly marks a matcher that never establishes a match by itself:
	// it runs only after the signature matched ("or"), to read a version
	// (e.g. a /readme.html probe sent to WordPress sites only).
	VersionOnly bool `yaml:"version_only,omitempty"`

	// header: Name + optional Regex (presence only if empty).
	// cookie: Name (exact, case-insensitive) or Regex over cookie names.
	Name  string `yaml:"name,omitempty"`
	Regex string `yaml:"regex,omitempty"` // title/body/header/cookie/hostname; path: response body

	// status / path: accepted status codes.
	Status []int `yaml:"status,omitempty"`

	// favicon: Shodan-compatible mmh3 hashes.
	Hashes []int32 `yaml:"hashes,omitempty"`

	// path probe: one extra GET/HEAD request.
	Path        string            `yaml:"path,omitempty"`
	Method      string            `yaml:"method,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty"` // request headers (no auth)
	Body        string            `yaml:"body,omitempty"`    // request body: always rejected
	Header      string            `yaml:"header,omitempty"`  // response header name to check
	HeaderRegex string            `yaml:"header_regex,omitempty"`

	// tls: flags that must all be true on the leaf certificate.
	Expired    bool `yaml:"expired,omitempty"`
	SelfSigned bool `yaml:"self_signed,omitempty"`
	Mismatch   bool `yaml:"hostname_mismatch,omitempty"`

	// service: nmap fields (no HTTP needed).
	Product string `yaml:"product,omitempty"` // regex over product + version
	Banner  string `yaml:"banner,omitempty"`  // regex over banner + extrainfo
	Ports   []int  `yaml:"ports,omitempty"`

	re       *regexp.Regexp
	hdrRe    *regexp.Regexp
	prodRe   *regexp.Regexp
	bannerRe *regexp.Regexp
}

var (
	idRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,63}$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// ValidationError lists every problem found in a signature.
type ValidationError struct {
	ID       string
	Problems []string
}

func (e *ValidationError) Error() string {
	id := e.ID
	if id == "" {
		id = "?"
	}
	return fmt.Sprintf("signature %s: %s", id, strings.Join(e.Problems, "; "))
}

// Parse decodes and validates one signature document. Unknown fields are
// rejected, so request bodies, payloads or methods cannot be smuggled in
// under other names.
func Parse(data []byte) (*Signature, error) {
	if len(data) > MaxYAMLBytes {
		return nil, fmt.Errorf("signature too large: %d bytes (max %d)", len(data), MaxYAMLBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Signature
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty signature")
		}
		return nil, fmt.Errorf("yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("one signature per document expected")
	}
	s.Raw = string(data)
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks the safety rules and compiles regular expressions.
func (s *Signature) Validate() error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }

	if !idRe.MatchString(s.ID) {
		add("id must match %s", idRe)
	}
	if strings.TrimSpace(s.Name) == "" || len(s.Name) > 128 {
		add("name is required (max 128 chars)")
	}
	if !contains(Categories, s.Category) {
		add("category must be one of %s", strings.Join(Categories, "|"))
	}
	if s.Confidence < 1 || s.Confidence > 100 {
		add("confidence must be 1-100")
	}
	switch s.Condition {
	case "", "or", "and":
	default:
		add("condition must be or|and")
	}
	if s.Severity != "" && !contains(Severities, s.Severity) {
		add("severity must be one of %s", strings.Join(Severities, "|"))
	}
	if o := s.Outdated; o != nil {
		if _, ok := parseVersion(o.Below); !ok {
			add("outdated.below must be a dotted version such as 6.0")
		}
		if !contains(Severities, o.Severity) {
			add("outdated.severity must be one of %s", strings.Join(Severities, "|"))
		}
	}
	if len(s.Matchers) == 0 {
		add("at least one matcher is required")
	}
	if len(s.Matchers) > MaxMatchers {
		add("too many matchers (max %d)", MaxMatchers)
	}
	paths := map[string]bool{}
	establishing := 0
	for i := range s.Matchers {
		m := &s.Matchers[i]
		pre := fmt.Sprintf("matcher %d (%s)", i+1, m.Type)
		for _, e := range m.validate() {
			add("%s: %s", pre, e)
		}
		if !m.VersionOnly {
			establishing++
		} else {
			if s.Condition == "and" {
				add("%s: version_only requires condition or", pre)
			}
			if m.Negate {
				add("%s: version_only cannot be negated", pre)
			}
			if !m.hasVersionGroup() {
				add("%s: version_only needs a regex with a named group (?P<version>...)", pre)
			}
		}
		if m.Type == TypePath {
			paths[m.Path] = true
		}
	}
	if len(s.Matchers) > 0 && establishing == 0 {
		add("at least one matcher must not be version_only")
	}
	if len(paths) > MaxPaths {
		add("too many extra paths: %d (max %d)", len(paths), MaxPaths)
	}
	if len(p) > 0 {
		return &ValidationError{ID: s.ID, Problems: p}
	}
	return nil
}

func (m *MatcherSpec) validate() []string {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	compile := func(field, expr string) *regexp.Regexp {
		if expr == "" {
			return nil
		}
		if len(expr) > 1024 {
			add("%s regex too long", field)
			return nil
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			add("%s regex: %v", field, err)
			return nil
		}
		return re
	}
	// Fields that only make sense on a path probe.
	if m.Type != TypePath {
		if m.Path != "" || m.Method != "" || len(m.Headers) > 0 || m.Header != "" || m.HeaderRegex != "" {
			add("path/method/headers/header only allowed on type path")
		}
	}
	if m.Body != "" {
		add("request body is not allowed")
	}
	switch m.Type {
	case TypeHeader:
		if !headerNameRe.MatchString(m.Name) {
			add("name must be a header name")
		}
		m.re = compile("regex", m.Regex)
	case TypeCookie:
		if m.Name == "" && m.Regex == "" {
			add("name or regex is required")
		}
		m.re = compile("regex", m.Regex)
	case TypeTitle, TypeBody, TypeHostname:
		if m.Regex == "" {
			add("regex is required")
		}
		m.re = compile("regex", m.Regex)
	case TypeFavicon:
		if len(m.Hashes) == 0 {
			add("hashes are required")
		}
	case TypeStatus:
		if len(m.Status) == 0 {
			add("status codes are required")
		}
		p = append(p, checkCodes(m.Status)...)
	case TypePath:
		switch strings.ToUpper(m.Method) {
		case "", "GET", "HEAD":
			m.Method = strings.ToUpper(m.Method)
			if m.Method == "" {
				m.Method = "GET"
			}
		default:
			add("method %q not allowed (only GET or HEAD)", m.Method)
		}
		if err := checkPath(m.Path); err != "" {
			add("%s", err)
		}
		if len(m.Headers) > maxHeaders {
			add("too many request headers (max %d)", maxHeaders)
		}
		for k, v := range m.Headers {
			switch {
			case !headerNameRe.MatchString(k):
				add("invalid request header name %q", k)
			case httpfp.IsSensitiveHeader(k):
				add("auth/credential header %q is not allowed", k)
			case strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Type"):
				add("request header %q is not allowed", k)
			case strings.ContainsAny(v, "\r\n") || len(v) > 256:
				add("invalid value for request header %q", k)
			}
		}
		if len(m.Status) == 0 && m.Regex == "" && m.Header == "" {
			add("path probe needs status, regex or header to check")
		}
		p = append(p, checkCodes(m.Status)...)
		if m.Header != "" && !headerNameRe.MatchString(m.Header) {
			add("header must be a header name")
		}
		if m.HeaderRegex != "" && m.Header == "" {
			add("header_regex requires header")
		}
		m.re = compile("regex", m.Regex)
		m.hdrRe = compile("header_regex", m.HeaderRegex)
	case TypeTLS:
		if !m.Expired && !m.SelfSigned && !m.Mismatch {
			add("set at least one of expired, self_signed, hostname_mismatch")
		}
	case TypeService:
		if m.Product == "" && m.Banner == "" && len(m.Ports) == 0 {
			add("product, banner or ports is required")
		}
		for _, port := range m.Ports {
			if port < 1 || port > 65535 {
				add("port %d out of range", port)
			}
		}
		m.prodRe = compile("product", m.Product)
		m.bannerRe = compile("banner", m.Banner)
	default:
		add("unknown matcher type (allowed: %s)", strings.Join(MatcherTypes, ", "))
	}
	if m.Type != TypeService && (m.Product != "" || m.Banner != "" || len(m.Ports) > 0) {
		add("product/banner/ports only allowed on type service")
	}
	if m.Type != TypeTLS && (m.Expired || m.SelfSigned || m.Mismatch) {
		add("expired/self_signed/hostname_mismatch only allowed on type tls")
	}
	if m.Negate {
		switch m.Type {
		case TypeService, TypeHeader, TypeTitle, TypeBody:
		default:
			add("negate only allowed on types service, header, title and body")
		}
	}
	if m.Type != TypeFavicon && len(m.Hashes) > 0 {
		add("hashes only allowed on type favicon")
	}
	if m.Type != TypeStatus && m.Type != TypePath && len(m.Status) > 0 {
		add("status only allowed on types status and path")
	}
	return p
}

func checkCodes(codes []int) []string {
	var p []string
	for _, c := range codes {
		if c < 100 || c > 599 {
			p = append(p, fmt.Sprintf("status %d out of range", c))
		}
	}
	return p
}

func checkPath(p string) string {
	switch {
	case p == "":
		return "path is required"
	case len(p) > maxPathLen:
		return "path too long"
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return "path must be absolute on the same host (start with a single /)"
	case strings.ContainsAny(p, "\r\n\t #\\") || strings.ContainsRune(p, 0):
		return "path contains forbidden characters"
	case strings.Contains(p, "..") || strings.Contains(strings.ToLower(p), "%2e%2e") || strings.Contains(strings.ToLower(p), "%2f"):
		return "path must not contain .. or encoded traversal"
	case strings.Contains(p, "://"):
		return "path must not contain a URL"
	case credentialQuery(p):
		return "path query must not carry credentials (no login attempts)"
	}
	return ""
}

// credentialParams are query parameter names that would turn a GET probe
// into a login or token attempt.
var credentialParams = []string{"pass", "pwd", "user", "login", "token", "secret", "auth", "key", "session", "cred"}

func credentialQuery(p string) bool {
	_, q, ok := strings.Cut(p, "?")
	if !ok {
		return false
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		return true
	}
	for name := range vals {
		n := strings.ToLower(name)
		for _, c := range credentialParams {
			if strings.Contains(n, c) {
				return true
			}
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// LoadFS loads every *.yaml / *.yml file in the root of fsys. All errors are
// collected; any invalid file fails the whole load. Duplicate IDs are errors.
func LoadFS(fsys fs.FS) ([]*Signature, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		ext := path.Ext(e.Name())
		if !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []*Signature
	var errs []error
	seen := map[string]string{}
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		s, err := Parse(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		if prev, dup := seen[s.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate id %q (also in %s)", n, s.ID, prev))
			continue
		}
		seen[s.ID] = n
		out = append(out, s)
	}
	return out, errors.Join(errs...)
}

// LoadDir loads signatures from a directory on disk.
func LoadDir(dir string) ([]*Signature, error) { return LoadFS(os.DirFS(dir)) }

// parseVersion splits a dotted version ("4.7", "6.4.2", "2.0.18-beta") into
// its leading numeric parts.
func parseVersion(v string) ([]int, bool) {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(v), ".") {
		n, digits := 0, 0
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
			digits++
			if digits > 9 {
				return nil, false
			}
		}
		if digits == 0 {
			break
		}
		out = append(out, n)
		if digits != len(part) {
			break // "18-beta": keep 18, ignore the suffix and later parts
		}
	}
	return out, len(out) > 0
}

// CompareVersions compares two dotted versions numerically (missing parts
// count as 0). ok is false when either is not a version.
func CompareVersions(a, b string) (cmp int, ok bool) {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < max(len(va), len(vb)); i++ {
		x, y := 0, 0
		if i < len(va) {
			x = va[i]
		}
		if i < len(vb) {
			y = vb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// DojoSeverity maps a YAML severity to the DefectDojo spelling ("high" -> "High").
func DojoSeverity(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
