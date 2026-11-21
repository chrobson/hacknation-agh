package httpfp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/safety"
)

// Defaults for Options.
const (
	// DefaultTimeout tolerates slow links (e.g. 500 ms+ injected latency in
	// each direction, bandwidth limits or a slow connection close).
	DefaultTimeout      = 10 * time.Second
	DefaultRetries      = 1
	DefaultRetryBackoff = 250 * time.Millisecond
	DefaultMaxRedirects = 5
	DefaultMaxBody      = 2 << 20 // 2 MB
	DefaultUserAgent    = "asi-fingerprint/1.0 (+attack-surface-inventory)"
	maxFaviconBytes     = 1 << 20
	maxTitleRunes       = 512
)

// ErrMethodNotAllowed is returned when anything but GET or HEAD is requested.
var ErrMethodNotAllowed = errors.New("httpfp: only GET and HEAD are allowed")

// ErrNotAllowed is returned when the endpoint IP is rejected by Options.Allow.
var ErrNotAllowed = errors.New("httpfp: address outside the allowed networks")

// Options configure an HTTPProber. The zero value is usable.
type Options struct {
	// Timeout bounds every single request (connect + TLS + headers + body).
	Timeout time.Duration
	// Retries is how many times a request that failed with a timeout or a
	// dropped connection is repeated (0 = DefaultRetries, negative = none).
	// A refused connection or a rejected address is never retried.
	Retries int
	// RetryBackoff is the pause before a retry (0 = DefaultRetryBackoff).
	RetryBackoff time.Duration
	// MaxRedirects is the maximum number of redirect hops followed (<=5).
	MaxRedirects int
	// MaxBody caps the bytes read from a response body (<=2 MB).
	MaxBody int64
	// Limiter is a global rate limiter shared by all probes; every request
	// (redirect hops, favicon, path probes) waits on it. nil = unlimited.
	Limiter *rate.Limiter
	// UserAgent sent with every request.
	UserAgent string
	// Roots used for the separate certificate verification (nil = system).
	Roots *x509.CertPool
	// Now is the clock used for certificate expiry (nil = time.Now).
	Now func() time.Time
	// SkipFavicon disables favicon fetching.
	SkipFavicon bool
	// LatencySample enables one extra HEAD request to the first hop, on a
	// warm connection, after the probe; the stored response time is the
	// smaller of the two samples (cold starts otherwise show up as latency
	// changes between runs).
	LatencySample bool
	// DialContext overrides the network dialer (tests). It receives the
	// pinned "ip:port" address, never a hostname.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Allow, when set, is consulted before every probe and every dial (e.g.
	// target.Allowlist.AllowsAddr). A rejected address is never contacted.
	Allow func(netip.Addr) bool
}

// HTTPProber implements Prober. It only ever sends GET/HEAD requests, never
// sends credentials and dials only the endpoint's IP address: redirects to a
// different host are recorded but not followed, so a target cannot bounce the
// prober outside the allowlisted network.
type HTTPProber struct {
	opt Options
}

var _ Prober = (*HTTPProber)(nil)

// New returns a prober with defaults applied.
func New(opt Options) *HTTPProber {
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	switch {
	case opt.Retries == 0:
		opt.Retries = DefaultRetries
	case opt.Retries < 0:
		opt.Retries = 0
	case opt.Retries > 3:
		opt.Retries = 3
	}
	if opt.RetryBackoff <= 0 {
		opt.RetryBackoff = DefaultRetryBackoff
	}
	if opt.MaxRedirects <= 0 || opt.MaxRedirects > DefaultMaxRedirects {
		opt.MaxRedirects = DefaultMaxRedirects
	}
	if opt.MaxBody <= 0 || opt.MaxBody > DefaultMaxBody {
		opt.MaxBody = DefaultMaxBody
	}
	if opt.UserAgent == "" {
		opt.UserAgent = DefaultUserAgent
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.DialContext == nil {
		d := &net.Dialer{Timeout: opt.Timeout}
		opt.DialContext = d.DialContext
	}
	return &HTTPProber{opt: opt}
}

// Response is a single fetched resource.
type Response struct {
	URL     string
	Status  int
	Header  http.Header
	Cookies []*http.Cookie
	Body    []byte
	TLS     *tls.ConnectionState
	// Duration of the successful attempt: connect, TLS, headers and body.
	Duration time.Duration
}

// target describes where requests for one endpoint go.
type target struct {
	ip       string // literal IP the dialer is pinned to
	hostname string // host used in URLs/Host/SNI (vhost or IP)
}

func endpointTarget(ip, vhost string) target {
	t := target{ip: ip, hostname: ip}
	if vhost != "" {
		t.hostname = vhost
	}
	return t
}

// BaseURL returns scheme://host:port/ for an endpoint.
func BaseURL(ep model.Endpoint) string {
	scheme := ep.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := ep.Key.VHost
	if host == "" {
		host = ep.Key.IP.Unmap().String()
	}
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(int(ep.Key.Port))), Path: "/"}).String()
}

// client builds an http.Client pinned to t.ip that never follows redirects.
func (p *HTTPProber) client(t target, tlsCfg *tls.Config) *http.Client {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	tlsCfg.InsecureSkipVerify = true //nolint:gosec // we read the cert and verify separately
	if net.ParseIP(t.hostname) == nil {
		tlsCfg.ServerName = t.hostname
	}
	dial := p.opt.DialContext
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if err := p.check(t.ip); err != nil {
				return nil, err
			}
			return dial(ctx, network, net.JoinHostPort(t.ip, port))
		},
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    p.opt.Timeout,
		ResponseHeaderTimeout:  p.opt.Timeout,
		DisableKeepAlives:      true,
		DisableCompression:     false,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		// Every request is counted (method, credentials, rate) in the
		// safety meter of its context, if any.
		Transport: safety.Transport(tr),
		Timeout:   p.opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// check enforces Options.Allow for a literal IP.
func (p *HTTPProber) check(ip string) error {
	if p.opt.Allow == nil {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !p.opt.Allow(a.Unmap()) {
		return fmt.Errorf("%w: %s", ErrNotAllowed, ip)
	}
	return nil
}

func (p *HTTPProber) wait(ctx context.Context) error {
	if p.opt.Limiter == nil {
		return nil
	}
	return p.opt.Limiter.Wait(ctx)
}

// fetch performs one GET/HEAD request without following redirects.
func (p *HTTPProber) fetch(ctx context.Context, c *http.Client, method, rawURL string, limit int64, extra http.Header) (*Response, error) {
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead {
		return nil, ErrMethodNotAllowed
	}
	if err := p.wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range extra {
		if isSensitiveHeader(k) {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", p.opt.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil && len(body) == 0 {
		return nil, err
	}
	return &Response{
		URL:      rawURL,
		Status:   resp.StatusCode,
		Header:   resp.Header,
		Cookies:  resp.Cookies(),
		Body:     body,
		TLS:      resp.TLS,
		Duration: time.Since(start),
	}, nil
}

// fetchRetry is fetch with Options.Retries retries after transient errors
// (timeouts, resets, a connection closed early).
func (p *HTTPProber) fetchRetry(ctx context.Context, c *http.Client, method, rawURL string, limit int64, extra http.Header) (*Response, error) {
	resp, err := p.fetch(ctx, c, method, rawURL, limit, extra)
	for i := 0; i < p.opt.Retries && err != nil && retryable(ctx, rawURL, err); i++ {
		t := time.NewTimer(p.opt.RetryBackoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, err
		case <-t.C:
		}
		resp, err = p.fetch(ctx, c, method, rawURL, limit, extra)
	}
	return resp, err
}

// retryable reports transient request errors worth one more attempt.
func retryable(ctx context.Context, rawURL string, err error) bool {
	if ctx.Err() != nil || errors.Is(err, ErrNotAllowed) || errors.Is(err, ErrMethodNotAllowed) {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false // nothing listens: retrying cannot help
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// Handshake failures over TLS are handled by the legacy-TLS retry.
	if strings.HasPrefix(rawURL, "https:") && isTLSHandshakeError(err) {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset")
}

// isSensitiveHeader reports request headers that could carry credentials.
func isSensitiveHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	return strings.Contains(n, "auth") || strings.Contains(n, "token") ||
		strings.Contains(n, "api-key") || strings.Contains(n, "apikey") ||
		strings.Contains(n, "secret") || strings.Contains(n, "session") ||
		strings.Contains(n, "password")
}

// IsSensitiveHeader is exported for the signature validator.
func IsSensitiveHeader(name string) bool { return isSensitiveHeader(name) }

// Probe implements Prober.
func (p *HTTPProber) Probe(ctx context.Context, ep model.Endpoint) (model.HTTPObs, error) {
	obs := model.HTTPObs{ServiceID: ep.ServiceID}
	if !ep.Key.IP.IsValid() {
		return obs, errors.New("httpfp: endpoint without IP")
	}
	if ep.Scheme != "" && ep.Scheme != "http" && ep.Scheme != "https" {
		return obs, fmt.Errorf("httpfp: unsupported scheme %q", ep.Scheme)
	}
	t := endpointTarget(ep.Key.IP.Unmap().String(), ep.Key.VHost)
	if err := p.check(t.ip); err != nil {
		return obs, err
	}
	c := p.client(t, nil)
	defer func() { c.CloseIdleConnections() }()
	legacyTried := false

	cur := BaseURL(ep)
	obs.URL = cur
	cookies := map[string]model.Cookie{}
	var order []string
	var last *Response
	var tlsState *tls.ConnectionState
	for {
		resp, err := p.fetchRetry(ctx, c, http.MethodGet, cur, p.opt.MaxBody, nil)
		if err != nil && !legacyTried && ctx.Err() == nil && !errors.Is(err, ErrNotAllowed) &&
			strings.HasPrefix(cur, "https:") && isTLSHandshakeError(err) {
			// Old devices often speak only TLS 1.0/1.1 or RSA-kex/3DES suites,
			// which Go no longer offers by default: retry once with them.
			legacyTried = true
			c.CloseIdleConnections()
			c = p.client(t, legacyClientConfig())
			resp, err = p.fetch(ctx, c, http.MethodGet, cur, p.opt.MaxBody, nil)
		}
		if err != nil {
			if last == nil {
				return obs, fmt.Errorf("httpfp: GET %s: %w", cur, err)
			}
			break // keep what we have from earlier hops
		}
		last = resp
		obs.URL = cur
		if obs.ResponseMS == 0 {
			// The first hop answers for this service (later hops may be
			// another port after a redirect).
			obs.ResponseMS = max(1, int(resp.Duration.Milliseconds()))
		}
		// Only the first hop is this service; a plain-http service that
		// redirects to https must not inherit the certificate of port 443.
		if resp.TLS != nil && tlsState == nil && len(obs.Redirects) == 0 {
			tlsState = resp.TLS
		}
		for _, ck := range resp.Cookies {
			if _, seen := cookies[ck.Name]; !seen {
				order = append(order, ck.Name)
			}
			cookies[ck.Name] = model.Cookie{
				Name: ck.Name, Secure: ck.Secure, HTTPOnly: ck.HttpOnly, SameSite: sameSite(ck.SameSite),
			}
		}
		if !isRedirect(resp.Status) {
			break
		}
		if len(obs.Redirects) >= p.opt.MaxRedirects {
			break // hop limit reached: the last response stays a 3xx
		}
		// Each recorded hop is the redirecting URL with its status; the
		// Location it pointed to becomes the next hop (or obs.URL).
		loc := resp.Header.Get("Location")
		obs.Redirects = append(obs.Redirects, model.Redirect{URL: cur, Status: resp.Status})
		next, ok := resolveSameHost(cur, loc, t.hostname)
		if !ok {
			// Off-host or non-HTTP target: recorded with Status 0 (not
			// fetched) so the chain shows where it leads, never followed.
			if loc != "" && len(obs.Redirects) < p.opt.MaxRedirects {
				obs.Redirects = append(obs.Redirects, model.Redirect{URL: absOrRaw(cur, loc), Status: 0})
			}
			break
		}
		cur = next
	}

	obs.Status = last.Status
	obs.Headers = cleanHeaders(last.Header)
	for _, n := range order {
		obs.Cookies = append(obs.Cookies, cookies[n])
	}
	obs.Body = last.Body
	sum := sha256.Sum256(last.Body)
	obs.BodySHA256 = hex.EncodeToString(sum[:])
	obs.Title = ExtractTitle(last.Body)
	if tlsState != nil {
		obs.TLS = p.tlsInfo(tlsState, t.hostname)
	}
	if !p.opt.SkipFavicon {
		if h, ok := p.favicon(ctx, c, obs.URL, last.Body, t.hostname); ok {
			obs.FaviconMMH3 = &h
		}
	}
	// The first request often pays for a cold start (JIT, template caches,
	// a new connection), which made runs differ by hundreds of ms on healthy
	// services. A second, warm HEAD to the first hop gives a steadier sample;
	// the smaller of the two is stored. An injected delay (e.g. a latency
	// toxic) slows every response, so it still shows.
	if p.opt.LatencySample && obs.ResponseMS > 0 {
		if r, err := p.fetch(ctx, c, http.MethodHead, BaseURL(ep), 0, nil); err == nil {
			obs.ResponseMS = min(obs.ResponseMS, max(1, int(r.Duration.Milliseconds())))
		}
	}
	return obs, nil
}

func isRedirect(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func sameSite(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	}
	return ""
}

// cleanHeaders copies headers and drops Set-Cookie (values are never stored).
func cleanHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

func absOrRaw(base, loc string) string {
	b, err := url.Parse(base)
	if err != nil {
		return loc
	}
	r, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return b.ResolveReference(r).String()
}

// resolveSameHost resolves loc against base and reports whether it stays on
// the same host (scheme and port may change). Only http/https are followed.
func resolveSameHost(base, loc, host string) (string, bool) {
	if loc == "" {
		return "", false
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(loc)
	if err != nil {
		return "", false
	}
	u := b.ResolveReference(r)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if !strings.EqualFold(u.Hostname(), host) {
		return "", false
	}
	// The port may only change to the default port of the (new) scheme, e.g.
	// http://h:80 -> https://h/. Anything else could aim an HTTP request at
	// an unrelated service on the same host.
	if effectivePort(u) != effectivePort(b) && u.Port() != "" && u.Port() != defaultPort(u.Scheme) {
		return "", false
	}
	u.Fragment = ""
	return u.String(), true
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaceRe = regexp.MustCompile(`\s+`)
)

// ExtractTitle returns the unescaped, whitespace-collapsed <title> text.
func ExtractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(spaceRe.ReplaceAllString(html.UnescapeString(string(m[1])), " "))
	if r := []rune(t); len(r) > maxTitleRunes {
		t = string(r[:maxTitleRunes])
	}
	return t
}

var (
	linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	relRe     = regexp.MustCompile(`(?is)\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	hrefRe    = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

func attr(re *regexp.Regexp, tag string) string {
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return html.UnescapeString(g)
		}
	}
	return ""
}

// FaviconLinks returns the href values of <link rel="...icon..."> tags.
func FaviconLinks(body []byte) []string {
	var out []string
	for _, tag := range linkTagRe.FindAllString(string(body), 20) {
		rel := strings.ToLower(attr(relRe, tag))
		if !strings.Contains(rel, "icon") || strings.Contains(rel, "mask-icon") {
			continue
		}
		if h := attr(hrefRe, tag); h != "" && !strings.HasPrefix(strings.ToLower(h), "data:") {
			out = append(out, h)
		}
	}
	return out
}

// favicon tries <link rel=icon> targets (same host only) then /favicon.ico.
func (p *HTTPProber) favicon(ctx context.Context, c *http.Client, pageURL string, body []byte, host string) (int32, bool) {
	var cands []string
	for _, h := range FaviconLinks(body) {
		if u, ok := resolveSameHost(pageURL, h, host); ok {
			cands = append(cands, u)
		}
		if len(cands) == 2 {
			break
		}
	}
	if u, ok := resolveSameHost(pageURL, "/favicon.ico", host); ok {
		cands = append(cands, u)
	}
	seen := map[string]bool{}
	for _, u := range cands {
		if seen[u] {
			continue
		}
		seen[u] = true
		resp, err := p.fetch(ctx, c, http.MethodGet, u, maxFaviconBytes, nil)
		if err != nil || resp.Status != http.StatusOK || len(resp.Body) == 0 {
			continue
		}
		if looksLikeHTML(resp) {
			continue // soft-404 page, not an icon
		}
		return FaviconHash(resp.Body), true
	}
	return 0, false
}

func looksLikeHTML(r *Response) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/html") {
		return true
	}
	head := bytes.ToLower(bytes.TrimSpace(r.Body[:min(len(r.Body), 64)]))
	return bytes.HasPrefix(head, []byte("<!doctype html")) || bytes.HasPrefix(head, []byte("<html"))
}

// FetchPath performs a single GET/HEAD of path on the origin of baseURL,
// dialing ip only, without following redirects. Used by signature path
// probes; it satisfies sig.Fetcher via the Fetcher adapter.
func (p *HTTPProber) FetchPath(ctx context.Context, ip, vhost, baseURL, method, path string, hdr http.Header) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return nil, fmt.Errorf("httpfp: invalid probe path %q", path)
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if b.Scheme != "http" && b.Scheme != "https" {
		return nil, fmt.Errorf("httpfp: unsupported scheme %q", b.Scheme)
	}
	t := endpointTarget(ip, vhost)
	if err := p.check(t.ip); err != nil {
		return nil, err
	}
	if !strings.EqualFold(b.Hostname(), t.hostname) {
		return nil, fmt.Errorf("httpfp: base URL host %q is not the endpoint host", b.Hostname())
	}
	u := &url.URL{Scheme: b.Scheme, Host: b.Host}
	ref, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u = u.ResolveReference(ref)
	c := p.client(t, nil)
	defer c.CloseIdleConnections()
	return p.fetchRetry(ctx, c, method, u.String(), p.opt.MaxBody, hdr)
}

// Timeout returns the per-request timeout in effect.
func (p *HTTPProber) Timeout() time.Duration { return p.opt.Timeout }
