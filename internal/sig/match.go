package sig

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// ProbeRequest is an extra request issued by a path matcher.
type ProbeRequest struct {
	Method  string // GET | HEAD
	Path    string
	Headers map[string]string
}

// ProbeResponse is the result of a ProbeRequest.
type ProbeResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// Fetcher performs path probes on the service's own origin. Implementations
// must only send GET/HEAD and never follow redirects to other hosts.
type Fetcher interface {
	Fetch(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs, req ProbeRequest) (ProbeResponse, error)
}

// Engine implements Matcher over a set of validated signatures.
type Engine struct {
	mu   sync.RWMutex
	sigs []*Signature

	// Fetcher runs path probes; nil disables them (path matchers never match).
	Fetcher Fetcher
	// ProbeTimeout bounds all path probes of one Match call (default 20s).
	ProbeTimeout time.Duration
}

var _ Matcher = (*Engine)(nil)

// NewEngine builds an engine. Signatures must come from Parse/LoadFS.
func NewEngine(sigs []*Signature, f Fetcher) *Engine {
	return &Engine{sigs: sigs, Fetcher: f}
}

// SetSignatures atomically replaces the active signature set.
func (e *Engine) SetSignatures(sigs []*Signature) {
	e.mu.Lock()
	e.sigs = sigs
	e.mu.Unlock()
}

// Signatures returns the active signature set.
func (e *Engine) Signatures() []*Signature {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return slices.Clone(e.sigs)
}

// Match implements Matcher using a background context bounded by ProbeTimeout.
func (e *Engine) Match(svc model.ServiceObs, obs model.HTTPObs) []model.Detection {
	t := e.ProbeTimeout
	if t <= 0 {
		t = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	return e.MatchContext(ctx, svc, obs)
}

// MatchContext evaluates all signatures. Path probes are cached per call so
// several signatures probing the same path cost one request.
func (e *Engine) MatchContext(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs) []model.Detection {
	ev := &evaluator{ctx: ctx, svc: svc, obs: obs, fetcher: e.Fetcher, cache: map[string]*ProbeResponse{}}
	var out []model.Detection
	for _, s := range e.Signatures() {
		if evidence, ok := ev.signature(s); ok {
			out = append(out, model.Detection{
				ServiceID:   svc.ID,
				SignatureID: s.ID,
				Name:        s.Name,
				Category:    s.Category,
				Confidence:  s.Confidence,
				Evidence:    evidence,
			})
		}
	}
	return SuppressGeneric(out)
}

// GenericPanels are catch-all panel signatures (a password field, /admin).
// They are dropped when a product-specific panel or device UI on the same
// service already explains the login form.
var GenericPanels = map[string]bool{"login-page": true, "admin-panel": true}

// SuppressGeneric removes GenericPanels detections when another admin-panel
// or iot detection matched the same service.
func SuppressGeneric(ds []model.Detection) []model.Detection {
	specific := false
	for _, d := range ds {
		if !GenericPanels[d.SignatureID] && (d.Category == "admin-panel" || d.Category == "iot") {
			specific = true
			break
		}
	}
	if !specific {
		return ds
	}
	out := ds[:0]
	for _, d := range ds {
		if !GenericPanels[d.SignatureID] {
			out = append(out, d)
		}
	}
	return out
}

type evaluator struct {
	ctx     context.Context
	svc     model.ServiceObs
	obs     model.HTTPObs
	fetcher Fetcher
	cache   map[string]*ProbeResponse // nil value = probe failed
	version string                    // set by find on a "version" group
}

func (ev *evaluator) hasHTTP() bool { return ev.obs.Status != 0 }

// signature evaluates passive matchers first, then path probes, with
// short-circuiting so a failed "and" or a satisfied "or" sends no requests.
func (ev *evaluator) signature(s *Signature) (map[string]string, bool) {
	and := s.Condition == "and"
	evidence := map[string]string{}
	ordered := make([]*MatcherSpec, 0, len(s.Matchers))
	for i := range s.Matchers {
		if s.Matchers[i].Type != TypePath {
			ordered = append(ordered, &s.Matchers[i])
		}
	}
	for i := range s.Matchers {
		if s.Matchers[i].Type == TypePath {
			ordered = append(ordered, &s.Matchers[i])
		}
	}
	matched := false
	for _, m := range ordered {
		ev.version = ""
		key, val, ok := ev.matcher(m)
		if ok {
			evidence[key] = clip(val)
			if ev.version != "" && evidence["version"] == "" {
				evidence["version"] = clip(ev.version)
			}
			matched = true
			if !and {
				break
			}
		} else if and {
			return nil, false
		}
	}
	if !matched {
		return nil, false
	}
	return evidence, true
}

func clip(s string) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= 200 {
		return s
	}
	cut := 200
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func headerValues(h map[string][]string, name string) []string {
	if v, ok := h[http.CanonicalHeaderKey(name)]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// find returns the full match of m.re in s. A named group "version", when
// it participated, is remembered and stored as evidence["version"].
func (ev *evaluator) find(m *MatcherSpec, s string) (string, bool) {
	loc := m.re.FindStringSubmatchIndex(s)
	if loc == nil {
		return "", false
	}
	if i := m.re.SubexpIndex("version"); i > 0 && loc[2*i] >= 0 && loc[2*i+1] > loc[2*i] {
		ev.version = s[loc[2*i]:loc[2*i+1]]
	}
	return s[loc[0]:loc[1]], true
}

// matcher returns an evidence key/value when m matches.
func (ev *evaluator) matcher(m *MatcherSpec) (string, string, bool) {
	switch m.Type {
	case TypeService:
		return ev.service(m)
	case TypeHostname:
		for _, h := range ev.hostnames() {
			if _, ok := ev.find(m, h); ok {
				return "hostname", h, true
			}
		}
		if !ev.hasHTTP() {
			return "", "", false
		}
	}
	if !ev.hasHTTP() {
		return "", "", false
	}
	switch m.Type {
	case TypeHeader:
		vals := headerValues(ev.obs.Headers, m.Name)
		if vals == nil {
			return "", "", false
		}
		if m.re == nil {
			return "header:" + m.Name, strings.Join(vals, ", "), true
		}
		for _, v := range vals {
			if got, ok := ev.find(m, v); ok {
				return "header:" + m.Name, got, true
			}
		}
	case TypeCookie:
		for _, c := range ev.obs.Cookies {
			if m.Name != "" && strings.EqualFold(c.Name, m.Name) {
				return "cookie", c.Name, true
			}
			if m.re != nil && m.re.MatchString(c.Name) {
				return "cookie", c.Name, true
			}
		}
	case TypeTitle:
		if v, ok := ev.find(m, ev.obs.Title); ok {
			return "title", v, true
		}
	case TypeBody:
		if v, ok := ev.find(m, string(ev.obs.Body)); ok {
			return "body", v, true
		}
	case TypeFavicon:
		if ev.obs.FaviconMMH3 != nil && slices.Contains(m.Hashes, *ev.obs.FaviconMMH3) {
			return "favicon_mmh3", strconv.Itoa(int(*ev.obs.FaviconMMH3)), true
		}
	case TypeStatus:
		if slices.Contains(m.Status, ev.obs.Status) {
			return "status", strconv.Itoa(ev.obs.Status), true
		}
	case TypeTLS:
		t := ev.obs.TLS
		if t == nil {
			return "", "", false
		}
		if (m.Expired && !t.Expired) || (m.SelfSigned && !t.SelfSigned) || (m.Mismatch && !t.Mismatch) {
			return "", "", false
		}
		var flags []string
		if m.Expired {
			flags = append(flags, "expired "+t.NotAfter.UTC().Format(time.DateOnly))
		}
		if m.SelfSigned {
			flags = append(flags, "self-signed")
		}
		if m.Mismatch {
			flags = append(flags, "hostname mismatch")
		}
		return "tls", strings.Join(flags, ", ") + "; subject=" + t.Subject, true
	case TypePath:
		return ev.path(m)
	}
	return "", "", false
}

func (ev *evaluator) service(m *MatcherSpec) (string, string, bool) {
	if len(m.Ports) > 0 && !slices.Contains(m.Ports, int(ev.svc.Key.Port)) {
		return "", "", false
	}
	val := "port " + strconv.Itoa(int(ev.svc.Key.Port))
	if m.prodRe != nil {
		s := strings.TrimSpace(ev.svc.Product + " " + ev.svc.Version)
		v := m.prodRe.FindString(s)
		if v == "" {
			return "", "", false
		}
		val = v
	}
	if m.bannerRe != nil {
		s := strings.TrimSpace(ev.svc.Banner + " " + ev.svc.ExtraInfo)
		v := m.bannerRe.FindString(s)
		if v == "" {
			return "", "", false
		}
		val = v
	}
	return "service", val, true
}

// hostnames lists names the service is known by: vhost, URL hosts in the
// redirect chain and certificate SANs / subject.
func (ev *evaluator) hostnames() []string {
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	add(ev.svc.Key.VHost)
	for _, raw := range append([]string{ev.obs.URL}, redirectURLs(ev.obs.Redirects)...) {
		if u, err := url.Parse(raw); err == nil {
			add(u.Hostname())
		}
	}
	if ev.obs.TLS != nil {
		for _, s := range ev.obs.TLS.SANs {
			add(s)
		}
		if cn := commonName(ev.obs.TLS.Subject); cn != "" {
			add(cn)
		}
	}
	return out
}

func redirectURLs(rs []model.Redirect) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.URL)
	}
	return out
}

func commonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return v
		}
	}
	return ""
}

func (ev *evaluator) path(m *MatcherSpec) (string, string, bool) {
	if ev.fetcher == nil || ev.obs.URL == "" {
		return "", "", false
	}
	key := m.Method + " " + m.Path
	resp, cached := ev.cache[key]
	if !cached {
		r, err := ev.fetcher.Fetch(ev.ctx, ev.svc, ev.obs, ProbeRequest{Method: m.Method, Path: m.Path, Headers: m.Headers})
		if err == nil {
			resp = &r
		}
		ev.cache[key] = resp
	}
	if resp == nil {
		return "", "", false
	}
	if len(m.Status) > 0 && !slices.Contains(m.Status, resp.Status) {
		return "", "", false
	}
	val := m.Path + " -> " + strconv.Itoa(resp.Status)
	if m.Header != "" {
		vals := headerValues(resp.Header, m.Header)
		if vals == nil {
			return "", "", false
		}
		if m.hdrRe != nil {
			hit := false
			for _, v := range vals {
				if s := m.hdrRe.FindString(v); s != "" {
					val += " " + m.Header + ": " + s
					hit = true
					break
				}
			}
			if !hit {
				return "", "", false
			}
		}
	}
	if m.re != nil {
		v, ok := ev.find(m, string(resp.Body))
		if !ok {
			return "", "", false
		}
		val += " body: " + v
	}
	return "path:" + m.Path, val, true
}
