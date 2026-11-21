package app

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/auth"
	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
	webassets "github.com/chrobson/hacknation-agh/web"
)

func TestHTTPScheme(t *testing.T) {
	svc := func(port uint16, banner string) model.ServiceObs {
		return model.ServiceObs{Key: model.AssetKey{IP: netip.MustParseAddr("10.20.0.10"), Port: port, Proto: "tcp"}, Banner: banner}
	}
	cases := []struct {
		s    model.ServiceObs
		want string
	}{
		{svc(80, "http"), "http"},
		{svc(443, "ssl/http"), "https"},
		{svc(8443, "https-alt"), "https"},
		{svc(443, "http"), "https"},
		{svc(8080, "http-proxy"), "http"},
		{svc(3000, "ppp"), "http"},
		{svc(22, "ssh"), ""},
		{svc(3306, "mysql"), ""},
		{svc(1883, "mqtt"), ""},
		{svc(9999, ""), ""},
		{svc(8443, "ssl/unknown"), "https"},
	}
	for _, c := range cases {
		if got := HTTPScheme(c.s); got != c.want {
			t.Errorf("HTTPScheme(%d %q) = %q, want %q", c.s.Key.Port, c.s.Banner, got, c.want)
		}
	}
	udp := svc(53, "domain")
	udp.Key.Proto = "udp"
	if HTTPScheme(udp) != "" {
		t.Error("udp must not be probed")
	}
}

func TestMergeDetections(t *testing.T) {
	a := []model.Detection{{SignatureID: "nginx", Confidence: 80}}
	b := []model.Detection{{SignatureID: "nginx", Confidence: 90}, {SignatureID: "staging-env", Confidence: 70}}
	got := mergeDetections(a, b)
	if len(got) != 2 || got[0].Confidence != 90 || got[1].SignatureID != "staging-env" {
		t.Fatalf("merge = %+v", got)
	}
}

func TestScore(t *testing.T) {
	exp := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	got := map[string]bool{"a": true, "b": true, "x": true}
	top := map[string]bool{"a": true, "b": true}
	m := score(exp, got, top)
	if m.TP != 2 || m.FP != 1 || m.FN != 2 || m.Precision != 0.667 || m.Recall != 0.5 || *m.RecallTop1000 != 1 {
		t.Fatalf("score = %+v", m)
	}
	if e := score(map[string]bool{}, map[string]bool{}, nil); e.Precision != 1 || e.Recall != 1 {
		t.Fatalf("empty = %+v", e)
	}
}

func TestPagesRender(t *testing.T) {
	p, err := NewPages(web.Deps{}, nil, context.Background(), webassets.Templates)
	if err != nil {
		t.Fatal(err)
	}
	u := &auth.User{ID: 1, Login: "admin", RoleName: auth.RoleAdmin, Perms: []string{"targets.read", "results.read", "scans.run", "export", "users.admin"}}
	now := time.Now()
	ms := int64(61000)
	run := RunRow{ID: 3, Status: "done", ChunksTotal: 64, ChunksDone: 64, StartedAt: &now, FinishedAt: &now, DurationMS: &ms}
	every := 60
	ws, we := 22*time.Hour, 6*time.Hour
	status := 200
	pages := map[string]any{
		"dashboard": Dashboard{RunID: 3, LatestRun: &run, ActiveRuns: []RunRow{{ID: 4, Status: "running", ChunksTotal: 10, ChunksDone: 3, StartedAt: &now}},
			ByCategory: []KV{{"admin-panel", 2}}, Notable: []Finding{{ServiceID: 1, IP: "10.20.9.110", Port: 80, Proto: "tcp", Name: "Panel", Category: "admin-panel"}},
			ChangeRunID: 3, ChangesByKind: []KV{{"new", 1}}, Changes: []ChangeRow{{Kind: "changed", IP: "10.20.40.70", Port: 80, Proto: "tcp", Old: "a", New: "b"}},
			StateCounts: []KV{{"unstable", 1}}, Unstable: []HostRow{{IP: "10.20.60.120", State: "unstable"}}},
		"scans": scansData{CanRun: true, HasRunner: true, Runs: []RunRow{run},
			Configs: []configRow{{ScanConfig: store.ScanConfig{ID: 1, Name: "lab", TopPorts: 1000, MaxRate: 1000, Workers: 4, WindowStart: &ws, WindowEnd: &we, EveryMinutes: &every, Enabled: true}, TargetsLabel: "wszystkie cele", LastRun: &run}}},
		"scan_form": scanFormData{New: false, Config: store.ScanConfig{ID: 1, Name: "lab", TargetIDs: []int64{2}, WindowStart: &ws, WindowEnd: &we},
			Targets: []model.Target{{ID: 2, Value: "10.20.0.0/18", Tags: []string{"lab"}}}},
		"results": resultsData{Run: &run, Runs: []RunRow{run}, Filter: ResultFilter{RunID: 3}, Categories: []string{"cms"},
			Services: []ServiceRow{{ID: 1, IP: "10.20.0.10", Port: 80, Proto: "tcp", Banner: "http", Status: &status, Title: "x",
				Detections: []DetectionTag{{Signature: "nginx", Name: "nginx", Category: "server", Confidence: 85}}}}},
		"service": serviceData{Service: ServiceDetail{ServiceRow: ServiceRow{ID: 1, IP: "10.20.0.11", Port: 443, Proto: "tcp"}, RunID: 3},
			HTTP: &model.HTTPObs{URL: "https://10.20.0.11/", Status: 200, Headers: map[string][]string{"Server": {"nginx"}},
				Cookies: []model.Cookie{{Name: "s"}}, Redirects: []model.Redirect{{URL: "https://x/", Status: 301}},
				TLS: &model.TLSInfo{Subject: "CN=secure.lab.local", SelfSigned: true}},
			Detections: []model.Detection{{SignatureID: "tls-self-signed", Name: "TLS", Category: "other", Evidence: map[string]string{"tls": "self-signed"}}},
			Legacy:     &httpfp.LegacyTLS{TLS10: true}},
	}
	for name, data := range pages {
		r := httptest.NewRequest("GET", "/", nil)
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		p.render(w, r, name, 200, page{Data: data})
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", name, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `hx-get="/nav"`) {
			t.Errorf("%s: shared nav missing", name)
		}
	}
	// nav hides items the user may not use
	viewer := &auth.User{ID: 2, Login: "viewer", Perms: []string{"targets.read", "results.read"}}
	r := httptest.NewRequest("GET", "/nav", nil)
	r = r.WithContext(auth.WithUser(r.Context(), viewer))
	w := httptest.NewRecorder()
	p.nav(w, r)
	body := w.Body.String()
	if !strings.Contains(body, "/results") || strings.Contains(body, "/admin/users") || strings.Contains(body, "/export") {
		t.Errorf("viewer nav = %s", body)
	}
	w = httptest.NewRecorder()
	p.nav(w, httptest.NewRequest("GET", "/nav", nil))
	if bytes.TrimSpace(w.Body.Bytes()) != nil && w.Body.Len() != 0 {
		t.Errorf("anonymous nav must be empty, got %q", w.Body.String())
	}
}
