package httpfp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// endpointFor converts an httptest server URL into a model.Endpoint.
func endpointFor(t *testing.T, rawURL, vhost string) model.Endpoint {
	t.Helper()
	scheme, hostport, _ := strings.Cut(rawURL, "://")
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return model.Endpoint{
		ServiceID: 7,
		Scheme:    scheme,
		Key:       model.AssetKey{IP: netip.MustParseAddr(host), Port: uint16(p), Proto: "tcp", VHost: vhost},
	}
}

var icon = []byte("\x00\x00\x01\x00\x01\x00\x10\x10test-icon-bytes")

func TestProbeRedirectsTitleCookiesFavicon(t *testing.T) {
	var methods atomic.Value
	methods.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		methods.Store(methods.Load().(string) + r.Method + " ")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "pre", Value: "SECRET-1", HttpOnly: true})
		http.Redirect(w, r, "/a", http.StatusFound)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?next=%2F", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "SECRET-2", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.Header().Set("Server", "TestServer/1.2")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><TITLE>  Panel &amp; logowanie
		</TITLE><link rel="shortcut icon" href="/static/i.ico"></head><body>x</body></html>`)
	})
	mux.HandleFunc("/static/i.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(icon)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{Timeout: 5 * time.Second})
	obs, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != 200 || obs.ServiceID != 7 {
		t.Fatalf("status=%d service=%d", obs.Status, obs.ServiceID)
	}
	if !strings.HasSuffix(obs.URL, "/login?next=%2F") {
		t.Errorf("final URL = %s", obs.URL)
	}
	if len(obs.Redirects) != 2 || obs.Redirects[0].Status != 302 || obs.Redirects[1].Status != 301 ||
		!strings.HasSuffix(obs.Redirects[0].URL, "/") || !strings.HasSuffix(obs.Redirects[1].URL, "/a") {
		t.Errorf("redirects = %+v", obs.Redirects)
	}
	if obs.Title != "Panel & logowanie" {
		t.Errorf("title = %q", obs.Title)
	}
	if _, ok := obs.Headers["Set-Cookie"]; ok {
		t.Error("Set-Cookie must not be kept in headers")
	}
	if obs.Headers["Server"][0] != "TestServer/1.2" {
		t.Errorf("headers = %v", obs.Headers)
	}
	if len(obs.Cookies) != 2 {
		t.Fatalf("cookies = %+v", obs.Cookies)
	}
	want := model.Cookie{Name: "sid", Secure: true, HTTPOnly: true, SameSite: "Strict"}
	if obs.Cookies[1] != want || obs.Cookies[0].Name != "pre" || !obs.Cookies[0].HTTPOnly {
		t.Errorf("cookies = %+v", obs.Cookies)
	}
	for _, c := range obs.Cookies {
		if strings.Contains(fmt.Sprint(c), "SECRET") {
			t.Error("cookie value leaked")
		}
	}
	sum := sha256.Sum256(obs.Body)
	if obs.BodySHA256 != hex.EncodeToString(sum[:]) || len(obs.Body) == 0 {
		t.Error("body hash mismatch")
	}
	if obs.FaviconMMH3 == nil || *obs.FaviconMMH3 != FaviconHash(icon) {
		t.Errorf("favicon = %v, want %d", obs.FaviconMMH3, FaviconHash(icon))
	}
	if m := methods.Load().(string); strings.Contains(m, "POST") || strings.Contains(m, "PUT") {
		t.Errorf("unexpected methods %q", m)
	}
}

func TestProbeRedirectLimit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		http.Redirect(w, r, "/r"+strconv.Itoa(int(n)), http.StatusFound)
	}))
	defer srv.Close()
	obs, err := New(Options{SkipFavicon: true}).Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Redirects) != 5 {
		t.Fatalf("recorded %d hops, want 5", len(obs.Redirects))
	}
	if got := hits.Load(); got != 6 {
		t.Fatalf("server saw %d requests, want 6 (5 followed redirects)", got)
	}
	if obs.Status != 302 {
		t.Fatalf("status = %d", obs.Status)
	}
}

func TestProbeDoesNotFollowOffHostRedirect(t *testing.T) {
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://sso.example.invalid/auth", http.StatusFound)
	}))
	defer srv.Close()
	d := &net.Dialer{}
	p := New(Options{SkipFavicon: true, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		dials.Add(1)
		return d.DialContext(ctx, n, a)
	}})
	obs, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dialed %d times, want 1", dials.Load())
	}
	if len(obs.Redirects) != 2 || obs.Redirects[1].URL != "http://sso.example.invalid/auth" || obs.Redirects[1].Status != 0 {
		t.Fatalf("redirects = %+v", obs.Redirects)
	}
}

func TestProbeBodyCap(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 3<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(big)
	}))
	defer srv.Close()
	obs, err := New(Options{SkipFavicon: true, MaxBody: 10 << 20}).Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Body) != DefaultMaxBody {
		t.Fatalf("body len = %d, want %d", len(obs.Body), DefaultMaxBody)
	}
}

func TestFaviconFallbackAndSoft404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.Write(icon)
		default:
			fmt.Fprint(w, "<html><title>x</title></html>")
		}
	}))
	defer srv.Close()
	obs, err := New(Options{}).Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.FaviconMMH3 == nil || *obs.FaviconMMH3 != FaviconHash(icon) {
		t.Fatalf("favicon = %v", obs.FaviconMMH3)
	}

	soft := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><html><title>Not here</title></html>")
	}))
	defer soft.Close()
	obs, err = New(Options{}).Probe(context.Background(), endpointFor(t, soft.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.FaviconMMH3 != nil {
		t.Fatal("HTML soft-404 must not be hashed as favicon")
	}
}

func TestRateLimiterIsShared(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	lim := rate.NewLimiter(rate.Every(40*time.Millisecond), 1)
	p := New(Options{SkipFavicon: true, Limiter: lim})
	ep := endpointFor(t, srv.URL, "")
	start := time.Now()
	for i := 0; i < 4; i++ {
		if _, err := p.Probe(context.Background(), ep); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 110*time.Millisecond {
		t.Fatalf("4 requests took %v; limiter not applied", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Probe(ctx, ep); err == nil {
		t.Fatal("cancelled context must fail")
	}
}

func TestFetchPathRules(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.Method+" "+r.URL.RequestURI()+" auth="+r.Header.Get("Authorization"))
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	ep := endpointFor(t, srv.URL, "")
	p := New(Options{})
	ip := ep.Key.IP.String()
	base := BaseURL(ep)
	r, err := p.FetchPath(context.Background(), ip, "", base, "GET", "/manager/html", http.Header{"Authorization": {"Basic eDp5"}, "X-Test": {"1"}})
	if err != nil || r.Status != 401 {
		t.Fatalf("status=%v err=%v", r, err)
	}
	r, err = p.FetchPath(context.Background(), ip, "", base, "HEAD", "/redir", nil)
	if err != nil || r.Status != 302 {
		t.Fatalf("redirect must not be followed: %v %v", r, err)
	}
	if _, err := p.FetchPath(context.Background(), ip, "", base, "POST", "/x", nil); !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("POST: %v", err)
	}
	for _, bad := range []string{"//evil.example/x", "x", ""} {
		if _, err := p.FetchPath(context.Background(), ip, "", base, "GET", bad, nil); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
	if _, err := p.FetchPath(context.Background(), ip, "", "http://other.example:1/", "GET", "/", nil); err == nil {
		t.Error("foreign base host accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != "GET /manager/html auth=" || !strings.HasPrefix(got[1], "HEAD /redir") {
		t.Fatalf("server saw %q", got)
	}
}

func TestExtractTitleAndLinks(t *testing.T) {
	if got := ExtractTitle([]byte("<title>a\n\tb</title>")); got != "a b" {
		t.Errorf("title %q", got)
	}
	if got := ExtractTitle([]byte("<html>none</html>")); got != "" {
		t.Errorf("title %q", got)
	}
	links := FaviconLinks([]byte(`<link rel="stylesheet" href="/a.css"><link href='/f.png' rel='icon'><link rel=mask-icon href=/m.svg><link rel="icon" href="data:,">`))
	if len(links) != 1 || links[0] != "/f.png" {
		t.Errorf("links %v", links)
	}
}

// --- TLS --------------------------------------------------------------------

type certOpts struct {
	notBefore, notAfter time.Time
	dns                 []string
	ips                 []net.IP
	parent              *x509.Certificate
	parentKey           any
	isCA                bool
	rsa                 bool
}

func makeCert(t *testing.T, o certOpts) (*x509.Certificate, tls.Certificate, any) {
	t.Helper()
	var key any
	var pub any
	if o.rsa {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "asi-test", Organization: []string{"ASI"}},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dns,
		IPAddresses:           o.ips,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
	}
	if o.isCA {
		tmpl.Subject.CommonName = "asi-test-ca"
	}
	parent, signer := tmpl, key
	if o.parent != nil {
		parent, signer = o.parent, o.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: c}, key
}

func tlsServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>secure</title>")
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTLSSelfSignedExpiredMismatch(t *testing.T) {
	now := time.Now()
	lo := []net.IP{net.ParseIP("127.0.0.1")}

	t.Run("self-signed valid", func(t *testing.T) {
		_, kp, _ := makeCert(t, certOpts{notBefore: now.Add(-time.Hour), notAfter: now.Add(24 * time.Hour), ips: lo})
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})
		obs, err := New(Options{SkipFavicon: true}).Probe(context.Background(), endpointFor(t, srv.URL, ""))
		if err != nil {
			t.Fatal(err)
		}
		if obs.TLS == nil || !obs.TLS.SelfSigned || obs.TLS.Expired || obs.TLS.Mismatch {
			t.Fatalf("tls = %+v", obs.TLS)
		}
		if obs.Title != "secure" || obs.TLS.Version == "" || obs.TLS.SANs[0] != "127.0.0.1" {
			t.Fatalf("obs = %+v tls=%+v", obs, obs.TLS)
		}
	})

	t.Run("expired", func(t *testing.T) {
		_, kp, _ := makeCert(t, certOpts{notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour), ips: lo})
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})
		obs, err := New(Options{SkipFavicon: true}).Probe(context.Background(), endpointFor(t, srv.URL, ""))
		if err != nil {
			t.Fatal(err)
		}
		if !obs.TLS.Expired || !obs.TLS.SelfSigned {
			t.Fatalf("tls = %+v", obs.TLS)
		}
	})

	t.Run("hostname mismatch via vhost, CA-signed", func(t *testing.T) {
		ca, _, caKey := makeCert(t, certOpts{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), isCA: true})
		_, kp, _ := makeCert(t, certOpts{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
			dns: []string{"app.lab.test"}, parent: ca, parentKey: caKey})
		srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}})
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		p := New(Options{SkipFavicon: true, Roots: roots})

		obs, err := p.Probe(context.Background(), endpointFor(t, srv.URL, "app.lab.test"))
		if err != nil {
			t.Fatal(err)
		}
		if obs.TLS.Mismatch || obs.TLS.SelfSigned || obs.TLS.Expired {
			t.Fatalf("matching vhost: tls = %+v", obs.TLS)
		}
		if !strings.HasPrefix(obs.URL, "https://app.lab.test:") {
			t.Fatalf("url = %s", obs.URL)
		}
		obs, err = p.Probe(context.Background(), endpointFor(t, srv.URL, "other.lab.test"))
		if err != nil {
			t.Fatal(err)
		}
		if !obs.TLS.Mismatch || obs.TLS.SelfSigned {
			t.Fatalf("other vhost: tls = %+v", obs.TLS)
		}
	})
}

func TestLegacyTLSProbe(t *testing.T) {
	now := time.Now()
	_, kp, _ := makeCert(t, certOpts{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), rsa: true,
		ips: []net.IP{net.ParseIP("127.0.0.1")}})

	legacy := tlsServer(t, &tls.Config{
		Certificates: []tls.Certificate{kp},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS11,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	})
	p := New(Options{})
	res, err := p.ProbeLegacyTLS(context.Background(), endpointFor(t, legacy.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !res.TLS10 || !res.TLS11 || res.TLS10Cipher == "" {
		t.Fatalf("legacy server: %+v", res)
	}

	modern := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12})
	res, err = p.ProbeLegacyTLS(context.Background(), endpointFor(t, modern.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.TLS10 || res.TLS11 {
		t.Fatalf("modern server: %+v", res)
	}
}

func TestCertInfoNotYetValidIsNotExpired(t *testing.T) {
	now := time.Now()
	c, _, _ := makeCert(t, certOpts{notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour), dns: []string{"a.test"}})
	info := CertInfo([]*x509.Certificate{c}, "a.test", nil, now, tls.VersionTLS13)
	if info.Expired || info.Mismatch || !info.SelfSigned || info.Version != "TLS 1.3" {
		t.Fatalf("info = %+v", info)
	}
}

func TestAllowGuard(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	deny := func(netip.Addr) bool { return false }
	p := New(Options{SkipFavicon: true, Allow: deny})
	ep := endpointFor(t, srv.URL, "")
	if _, err := p.Probe(context.Background(), ep); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Probe err = %v, want ErrNotAllowed", err)
	}
	if _, err := p.FetchPath(context.Background(), "127.0.0.1", "", srv.URL+"/", "GET", "/x", nil); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("FetchPath err = %v, want ErrNotAllowed", err)
	}
	if _, err := p.ProbeLegacyTLS(context.Background(), ep); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("ProbeLegacyTLS err = %v, want ErrNotAllowed", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("server contacted %d times", hits.Load())
	}
	allow := func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") }
	if _, err := New(Options{SkipFavicon: true, Allow: allow}).Probe(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectToOtherPortNotFollowed(t *testing.T) {
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:6379/", http.StatusFound)
	}))
	defer srv.Close()
	d := &net.Dialer{}
	p := New(Options{SkipFavicon: true, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
		dials.Add(1)
		return d.DialContext(ctx, n, a)
	}})
	obs, err := p.Probe(context.Background(), endpointFor(t, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 1 || len(obs.Redirects) != 2 || obs.Redirects[1].Status != 0 {
		t.Fatalf("dials=%d redirects=%+v", dials.Load(), obs.Redirects)
	}
	if got, ok := resolveSameHost("http://h:8080/", "https://h/", "h"); !ok || got != "https://h/" {
		t.Fatalf("upgrade to default https port should be followed: %q %v", got, ok)
	}
	if _, ok := resolveSameHost("http://h:8080/", "/next", "h"); !ok {
		t.Fatal("same-origin redirect should be followed")
	}
}

func TestProbeFallsBackToLegacyTLS(t *testing.T) {
	now := time.Now()
	_, kp, _ := makeCert(t, certOpts{notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour), rsa: true,
		ips: []net.IP{net.ParseIP("127.0.0.1")}})
	legacy := tlsServer(t, &tls.Config{
		Certificates: []tls.Certificate{kp},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	})
	obs, err := New(Options{SkipFavicon: true}).Probe(context.Background(), endpointFor(t, legacy.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status == 0 || obs.TLS == nil || obs.TLS.Version != "TLS 1.0" {
		t.Fatalf("obs = %+v tls=%+v", obs, obs.TLS)
	}
}
