package sig

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/scan"
)

// route is one canned HTTP response of a fixture site.
type route struct {
	status   int
	ctype    string
	file     string // under testdata/fixtures
	body     string // used when file is empty
	location string
	cookies  []string
}

// fixtureSite serves routes over a real httptest server (unknown paths are
// 404 "404 page not found", like Go and Traefik defaults) and records every
// request method and path.
func fixtureSite(t *testing.T, routes map[string]route) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		rt, ok := routes[r.URL.RequestURI()]
		if !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404 page not found\n"))
			return
		}
		for _, c := range rt.cookies {
			w.Header().Add("Set-Cookie", c)
		}
		if rt.ctype != "" {
			w.Header().Set("Content-Type", rt.ctype)
		}
		if rt.location != "" {
			w.Header().Set("Location", rt.location)
		}
		body := []byte(rt.body)
		if rt.file != "" {
			b, err := os.ReadFile(filepath.Join("testdata", "fixtures", rt.file))
			if err != nil {
				t.Error(err)
			}
			body = b
		}
		st := rt.status
		if st == 0 {
			st = http.StatusOK
		}
		w.WriteHeader(st)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// newSigIDs are the signatures added for the AGH lab template; a fixture
// must match exactly the expected subset of them (no false positives).
var newSigIDs = []string{"dvwa", "nginx-proxy-manager", "traefik-dashboard", "toxiproxy-api", "rabbitmq-management",
	"rabbitmq-amqp", "httpbin", "redis", "redis-noauth", "ftp", "vsftpd", "postgresql", "mysql",
	"wordpress", "adminer", "gitea", "phpmyadmin"}

type wantDet struct {
	id       string
	severity model.Severity
	version  string // "" = not checked
	outdated bool
}

func checkDetections(t *testing.T, ds []model.Detection, want []wantDet) {
	t.Helper()
	got := map[string]model.Detection{}
	for _, d := range ds {
		got[d.SignatureID] = d
	}
	var wantIDs, gotIDs []string
	for _, w := range want {
		wantIDs = append(wantIDs, w.id)
		d, ok := got[w.id]
		if !ok {
			continue
		}
		if sev := dojo.DetectionSeverity(d); sev != w.severity {
			t.Errorf("%s: severity %s, want %s (evidence %v)", w.id, sev, w.severity, d.Evidence)
		}
		if w.version != "" && d.Evidence["version"] != w.version {
			t.Errorf("%s: version %q, want %q (evidence %v)", w.id, d.Evidence["version"], w.version, d.Evidence)
		}
		if (d.Evidence["outdated"] != "") != w.outdated {
			t.Errorf("%s: outdated=%q, want %v", w.id, d.Evidence["outdated"], w.outdated)
		}
	}
	for id := range got {
		if slices.Contains(newSigIDs, id) {
			gotIDs = append(gotIDs, id)
		}
	}
	sort.Strings(wantIDs)
	sort.Strings(gotIDs)
	if !slices.Equal(wantIDs, gotIDs) {
		t.Errorf("detections %v, want %v (all: %v)", gotIDs, wantIDs, keys(got))
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestHTTPSignatureFixtures(t *testing.T) {
	html := "text/html; charset=UTF-8"
	cases := []struct {
		name   string
		routes map[string]route
		want   []wantDet
		probes []string // extra requests that must have been sent
		never  []string // requests that must not have been sent
	}{
		{name: "dvwa", routes: map[string]route{
			"/":          {status: 302, location: "login.php", cookies: []string{"PHPSESSID=8a1c2d3e4f; path=/", "security=impossible; path=/"}},
			"/login.php": {ctype: html, file: "dvwa/login.html"},
		}, want: []wantDet{{id: "dvwa", severity: model.SevHigh}}},
		{name: "nginx-proxy-manager", routes: map[string]route{
			"/":     {ctype: html, file: "nginx-proxy-manager/index.html"},
			"/api/": {ctype: "application/json; charset=utf-8", file: "nginx-proxy-manager/api.json"},
		}, want: []wantDet{{id: "nginx-proxy-manager", severity: model.SevMedium, version: "2"}}, probes: []string{"GET /api/"}},
		{name: "traefik-api-insecure", routes: map[string]route{
			"/":            {status: 302, location: "/dashboard/", ctype: html, body: `<a href="/dashboard/">Found</a>.`},
			"/dashboard/":  {ctype: html, file: "traefik/dashboard.html"},
			"/api/version": {ctype: "application/json", file: "traefik/version.json"},
		}, want: []wantDet{{id: "traefik-dashboard", severity: model.SevHigh, version: "2.10.7"}}, probes: []string{"GET /api/version"}},
		{name: "toxiproxy-api", routes: map[string]route{
			"/proxies": {ctype: "application/json", file: "toxiproxy/proxies.json"},
		}, want: []wantDet{{id: "toxiproxy-api", severity: model.SevHigh}}, probes: []string{"GET /proxies"}},
		{name: "toxiproxy-api-empty", routes: map[string]route{
			"/proxies": {ctype: "application/json", body: "{}"},
		}, want: []wantDet{{id: "toxiproxy-api", severity: model.SevHigh}}},
		{name: "rabbitmq-management", routes: map[string]route{
			"/": {ctype: html, file: "rabbitmq/index.html"},
		}, want: []wantDet{{id: "rabbitmq-management", severity: model.SevMedium}}},
		{name: "httpbin", routes: map[string]route{
			"/": {ctype: html, file: "httpbin/index.html"},
		}, want: []wantDet{{id: "httpbin", severity: model.SevLow, version: "0.9.2"}}},
		{name: "wordpress-4.7-not-installed", routes: map[string]route{
			"/":                      {status: 302, location: "/wp-admin/install.php"},
			"/wp-admin/install.php":  {ctype: html, file: "wordpress-4.7-install/install.html"},
			"/wp-admin/install.php/": {status: 404},
		}, want: []wantDet{{id: "wordpress", severity: model.SevHigh, version: "4.7", outdated: true}},
			never: []string{"GET /readme.html", "GET /feed/"}},
		{name: "wordpress-5.8-generator", routes: map[string]route{
			"/": {ctype: html, file: "wordpress-5.8/home.html", cookies: []string{"wordpress_test_cookie=WP+Cookie+check; path=/"}},
		}, want: []wantDet{{id: "wordpress", severity: model.SevHigh, version: "5.8.3", outdated: true}}},
		{name: "wordpress-version-from-readme", routes: map[string]route{
			"/":            {ctype: html, file: "wordpress-readme/home.html"},
			"/readme.html": {ctype: html, file: "wordpress-readme/readme.html"},
		}, want: []wantDet{{id: "wordpress", severity: model.SevHigh, version: "4.7", outdated: true}}, probes: []string{"GET /readme.html"}},
		{name: "wordpress-current", routes: map[string]route{
			"/": {ctype: html, body: `<html><head><title>Blog</title><meta name="generator" content="WordPress 6.6.2" /></head><body><link href="/wp-content/x.css"></body></html>`},
		}, want: []wantDet{{id: "wordpress", severity: model.SevInfo, version: "6.6.2"}}, never: []string{"GET /readme.html"}},
		{name: "adminer", routes: map[string]route{
			"/": {ctype: html, file: "adminer/index.html", cookies: []string{"adminer_key=0f1e2d3c; path=/; HttpOnly", "adminer_sid=9a8b7c; path=/; HttpOnly"}},
		}, want: []wantDet{{id: "adminer", severity: model.SevMedium}}},
		{name: "gitea", routes: map[string]route{
			"/": {ctype: html, file: "gitea/index.html", cookies: []string{"i_like_gitea=6c1e4f2a9b; Path=/; HttpOnly; SameSite=Lax"}},
		}, want: []wantDet{{id: "gitea", severity: model.SevInfo}}},
		{name: "phpmyadmin", routes: map[string]route{
			"/": {ctype: html, file: "phpmyadmin/index.html", cookies: []string{"phpMyAdmin=4f2b1c; path=/; HttpOnly; SameSite=Strict"}},
		}, want: []wantDet{{id: "phpmyadmin", severity: model.SevMedium}}},
		{name: "plain-nginx-no-false-positives", routes: map[string]route{
			"/": {ctype: html, body: "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>"},
		}, want: nil, never: []string{"GET /proxies", "GET /api/version", "GET /readme.html", "GET /feed/", "GET /api/"}},
	}
	sigs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, seen := fixtureSite(t, c.routes)
			host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
			p, _ := strconv.Atoi(port)
			s := model.ServiceObs{ID: 1, Key: model.AssetKey{IP: netip.MustParseAddr(host), Port: uint16(p), Proto: "tcp"}, Banner: "http"}
			prober := httpfp.New(httpfp.Options{Timeout: 5 * time.Second, SkipFavicon: true})
			obs, err := prober.Probe(context.Background(), model.Endpoint{ServiceID: 1, Key: s.Key, Scheme: "http"})
			if err != nil {
				t.Fatal(err)
			}
			if obs.ResponseMS <= 0 {
				t.Errorf("ResponseMS not recorded: %d", obs.ResponseMS)
			}
			ds := NewEngine(sigs, NewHTTPFetcher(prober)).MatchContext(context.Background(), s, obs)
			checkDetections(t, ds, c.want)
			reqs := seen()
			for _, r := range reqs {
				if !strings.HasPrefix(r, "GET ") && !strings.HasPrefix(r, "HEAD ") {
					t.Errorf("non GET/HEAD request %q", r)
				}
			}
			for _, want := range c.probes {
				if !slices.Contains(reqs, want) {
					t.Errorf("probe %q not sent: %v", want, reqs)
				}
			}
			for _, bad := range c.never {
				if slices.Contains(reqs, bad) {
					t.Errorf("unexpected probe %q: %v", bad, reqs)
				}
			}
		})
	}
}

func TestServiceSignatureFixtures(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "fixtures", "nmap", "services.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := scan.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	byPort := map[uint16]model.ServiceObs{}
	for i, s := range res.Services {
		s.ID = int64(i + 1)
		byPort[s.Key.Port] = s
	}
	sigs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	fetch := &fakeFetcher{}
	e := NewEngine(sigs, fetch)
	cases := []struct {
		port uint16
		want []wantDet
	}{
		{21, []wantDet{{id: "ftp", severity: model.SevLow}, {id: "vsftpd", severity: model.SevLow, version: "3.0.3"}}},
		{2121, []wantDet{{id: "ftp", severity: model.SevLow}, {id: "vsftpd", severity: model.SevHigh, version: "2.3.4", outdated: true}}},
		{3306, []wantDet{{id: "mysql", severity: model.SevHigh, version: "5.7.44", outdated: true}}},
		{3307, []wantDet{{id: "mysql", severity: model.SevMedium}}},
		{5673, []wantDet{{id: "rabbitmq-amqp", severity: model.SevLow, version: "3.12.12"}}},
		{6379, []wantDet{{id: "redis", severity: model.SevLow, version: "7.2.4"}, {id: "redis-noauth", severity: model.SevHigh, version: "7.2.4"}}},
		{6380, []wantDet{{id: "redis", severity: model.SevLow}}},
		{6381, []wantDet{{id: "redis", severity: model.SevLow}}},
		{15432, []wantDet{{id: "postgresql", severity: model.SevMedium}}}, // "9.6.0 or later": no version
	}
	for _, c := range cases {
		t.Run(strconv.Itoa(int(c.port)), func(t *testing.T) {
			s, ok := byPort[c.port]
			if !ok {
				t.Fatalf("port %d not in fixture", c.port)
			}
			checkDetections(t, e.MatchContext(context.Background(), s, model.HTTPObs{}), c.want)
		})
	}
	if len(fetch.calls) != 0 {
		t.Errorf("service-only matches sent HTTP probes: %v", fetch.calls)
	}
}

func TestDojoFindingsForLabSignatures(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	svcs := []dojo.Service{
		{ServiceObs: model.ServiceObs{Key: model.AssetKey{IP: ip, Port: 8090, Proto: "tcp"}},
			Detections: []model.Detection{{SignatureID: "wordpress", Name: "WordPress", Category: "cms", Confidence: 90,
				Evidence: map[string]string{"version": "4.7", "outdated": "version 4.7 < 6.0", "severity": "High"}}}},
		{ServiceObs: model.ServiceObs{Key: model.AssetKey{IP: ip, Port: 8086, Proto: "tcp"}},
			Detections: []model.Detection{{SignatureID: "traefik-dashboard", Name: "Traefik", Category: "admin-panel", Confidence: 90,
				Evidence: map[string]string{"severity": "High"}}}},
		{ServiceObs: model.ServiceObs{Key: model.AssetKey{IP: ip, Port: 81, Proto: "tcp"}},
			Detections: []model.Detection{{SignatureID: "nginx-proxy-manager", Name: "NPM", Category: "admin-panel", Confidence: 90}}},
	}
	fs := dojo.BuildFindings(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), svcs, nil)
	want := map[string]struct {
		sev   model.Severity
		title string
	}{
		"asi:sig:127.0.0.1:8090:wordpress":         {model.SevHigh, "Outdated software detected: WordPress 4.7"},
		"asi:sig:127.0.0.1:8086:traefik-dashboard": {model.SevHigh, "Admin panel detected: Traefik"},
		"asi:sig:127.0.0.1:81:nginx-proxy-manager": {model.SevMedium, "Admin panel detected: NPM"},
	}
	n := 0
	for _, f := range fs {
		w, ok := want[f.UniqueIDFromTool]
		if !ok {
			continue
		}
		n++
		if f.Severity != w.sev || f.Title != w.title {
			t.Errorf("%s: %s %q, want %s %q", f.UniqueIDFromTool, f.Severity, f.Title, w.sev, w.title)
		}
	}
	if n != len(want) {
		t.Fatalf("found %d of %d findings: %+v", n, len(want), fs)
	}
}

func TestPostgresVersionBound(t *testing.T) {
	sigs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(sigs, &fakeFetcher{})
	for version, want := range map[string]string{"9.6.0 or later": "", "16.0 - 16.2": "16.0", "16.4": "16.4"} {
		svc := model.ServiceObs{ID: 1, Key: model.AssetKey{IP: netip.MustParseAddr("127.0.0.1"), Port: 5432, Proto: "tcp"},
			Product: "PostgreSQL DB", Version: version, Banner: "postgresql"}
		var got *model.Detection
		for _, d := range e.MatchContext(context.Background(), svc, model.HTTPObs{}) {
			if d.SignatureID == "postgresql" {
				got = &d
			}
		}
		if got == nil {
			t.Fatalf("%q: postgresql not detected", version)
		}
		if got.Evidence["version"] != want {
			t.Errorf("%q: version %q, want %q", version, got.Evidence["version"], want)
		}
	}
}
