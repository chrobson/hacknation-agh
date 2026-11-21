//go:build integration

package diff

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

// testPool connects to ASI_TEST_DATABASE_URL, migrates and empties the
// tables this module touches. The database is wiped: never point it at real data.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE scan_runs, host_state, annotations, changes, diff_runs, audit_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	return pool
}

type labRun struct {
	hosts    []string
	services []model.ServiceObs
	chunks   []string
}

func insertRun(t *testing.T, pool *pgxpool.Pool, r labRun) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `INSERT INTO scan_runs (status, started_at, finished_at) VALUES ('done', now(), now()) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.chunks {
		if _, err := pool.Exec(ctx, `INSERT INTO scan_chunks (run_id, cidr, status) VALUES ($1, $2::cidr, 'done')`, id, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range r.hosts {
		if _, err := pool.Exec(ctx, `INSERT INTO host_obs (run_id, ip, up) VALUES ($1, $2::inet, true)`, id, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range r.services {
		if _, err := pool.Exec(ctx, `INSERT INTO services (run_id, ip, port, proto, vhost, product, version, extrainfo, cpe, banner)
			VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10)`,
			id, s.Key.IP.String(), int(s.Key.Port), s.Key.Proto, s.Key.VHost, s.Product, s.Version, s.ExtraInfo, s.CPE, s.Banner); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func TestApplyRunThreeRuns(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	runs := []labRun{
		{[]string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			svc(0, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(0, "10.20.24.30", 23, "BusyBox telnetd", ""),
			svc(0, "10.20.24.30", 22, "OpenSSH", "7.4"),
			svc(0, "10.20.60.120", 80, "busybox httpd", ""),
		}, []string{"10.20.0.0/18"}},
		{[]string{"10.20.0.10", "10.20.24.30"}, []model.ServiceObs{
			svc(0, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(0, "10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			svc(0, "10.20.24.30", 22, "OpenSSH", "8.9p1"),
		}, []string{"10.20.0.0/18"}},
		{[]string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			svc(0, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(0, "10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			svc(0, "10.20.24.30", 22, "OpenSSH", "8.9p1"),
			svc(0, "10.20.60.120", 80, "busybox httpd", ""),
		}, []string{"10.20.0.0/18"}},
	}
	want := [][]string{
		{},
		{
			`new 10.20.0.10:8080/tcp ""->"Werkzeug httpd 3.0.1"`,
			`changed 10.20.24.30:22/tcp version "7.4"->"8.9p1"`,
			`gone 10.20.24.30:23/tcp "BusyBox telnetd"->""`,
			`host_down 10.20.60.120 "up"->"down"`,
			`gone 10.20.60.120:80/tcp "busybox httpd"->""`,
		},
		{
			`host_up 10.20.60.120 ""->"up"`,
			`unstable 10.20.60.120 flips ""->"2"`,
			`new 10.20.60.120:80/tcp ""->"busybox httpd"`,
		},
	}

	// An annotation made before the rescans must survive them.
	annKey := model.AssetKey{IP: ip("10.20.24.30"), Port: 22, Proto: "tcp"}
	if _, err := store.UpsertAnnotation(ctx, pool, store.Annotation{Key: annKey, Comment: "stary OpenSSH", Tags: []string{"legacy"}, Severity: "Medium"}); err != nil {
		t.Fatal(err)
	}

	var ids []int64
	for i, r := range runs {
		id := insertRun(t, pool, r)
		ids = append(ids, id)
		res, err := ApplyRun(ctx, pool, id, testCfg, t0.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatalf("apply run %d: %v", id, err)
		}
		stored, err := store.ListChanges(ctx, pool, id)
		if err != nil {
			t.Fatal(err)
		}
		SortChanges(stored)
		if g := fmtChanges(stored); !reflect.DeepEqual(g, want[i]) {
			t.Errorf("run %d stored changes:\n got  %q\n want %q", id, g, want[i])
		}
		if len(res.Changes) != len(stored) {
			t.Errorf("run %d: result has %d changes, stored %d", id, len(res.Changes), len(stored))
		}
		for _, c := range stored {
			if c.RunID != id || (i > 0 && c.PrevRunID != ids[i-1]) {
				t.Errorf("run ids on %s: %d/%d", fmtChange(c), c.RunID, c.PrevRunID)
			}
		}
	}

	if _, err := ApplyRun(ctx, pool, ids[2], testCfg, t0); !errors.Is(err, ErrAlreadyApplied) {
		t.Errorf("re-apply: %v", err)
	}

	hs, err := store.ListHostStates(ctx, pool, "")
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, h := range hs {
		states[h.IP.String()] = string(h.State)
	}
	wantStates := map[string]string{"10.20.0.10": "up", "10.20.24.30": "up", "10.20.60.120": "unstable"}
	if !reflect.DeepEqual(states, wantStates) {
		t.Errorf("host states %v, want %v", states, wantStates)
	}
	for _, h := range hs {
		if h.IP.String() == "10.20.60.120" && len(h.Flips) != 3 {
			t.Errorf("flips stored: %+v", h.Flips)
		}
	}

	runsList, err := store.ListChangeRuns(ctx, pool, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runsList) != 3 || runsList[0].Total != 3 || runsList[1].Counts[model.ChangeGone] != 2 || !runsList[2].Applied || runsList[2].PrevRunID != 0 {
		t.Errorf("change runs: %+v", runsList)
	}

	a, err := store.GetAnnotation(ctx, pool, annKey)
	if err != nil || a.Comment != "stary OpenSSH" || a.Severity != "Medium" {
		t.Errorf("annotation after rescans: %+v %v", a, err)
	}

	// A run whose chunks do not cover a known host leaves it untouched and
	// does not report its services as gone.
	other := insertRun(t, pool, labRun{hosts: []string{"192.0.2.5"}, chunks: []string{"192.0.2.0/24"},
		services: []model.ServiceObs{svc(0, "192.0.2.5", 443, "nginx", "")}})
	res, err := ApplyRun(ctx, pool, other, testCfg, t0)
	if err != nil {
		t.Fatal(err)
	}
	if g := fmtChanges(res.Changes); !reflect.DeepEqual(g, []string{`host_up 192.0.2.5 ""->"up"`, `new 192.0.2.5:443/tcp ""->"nginx"`}) {
		t.Errorf("out-of-scope run changes: %q", g)
	}
}

func TestAnnotationsCRUDAndHTTP(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	k := model.AssetKey{IP: ip("10.20.0.10"), Port: 443, Proto: "tcp", VHost: "staging.lab"}

	if _, err := store.GetAnnotation(ctx, pool, k); !errors.Is(err, store.ErrAnnotationNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	a, err := store.UpsertAnnotation(ctx, pool, store.Annotation{Key: k, Comment: "test", Tags: []string{"a"}})
	if err != nil || a.Key != k || a.Severity != "" || a.UpdatedAt.IsZero() {
		t.Fatalf("insert: %+v %v", a, err)
	}
	a, err = store.UpsertAnnotation(ctx, pool, store.Annotation{Key: k, Comment: "zmieniony", Severity: "High", FalsePositive: true})
	if err != nil || a.Comment != "zmieniony" || len(a.Tags) != 0 || !a.FalsePositive {
		t.Fatalf("update: %+v %v", a, err)
	}
	host := model.AssetKey{IP: ip("10.20.0.10")}
	if _, err := store.UpsertAnnotation(ctx, pool, store.Annotation{Key: host, Comment: "host"}); err != nil {
		t.Fatal(err)
	}
	m, err := store.AnnotationsByIPs(ctx, pool, []netip.Addr{ip("10.20.0.10")})
	if err != nil || len(m) != 2 || m[host].Comment != "host" {
		t.Fatalf("by ips: %v %v", m, err)
	}
	all, err := store.ListAnnotations(ctx, pool, netip.Addr{})
	if err != nil || len(all) != 2 || all[0].Key != host {
		t.Fatalf("list: %+v %v", all, err)
	}

	// HTTP: editor saves through the form, reader sees it, delete removes it.
	allow := Access{
		Require: func(string) func(http.Handler) http.Handler { return func(h http.Handler) http.Handler { return h } },
		Can:     func(*http.Request, string) bool { return true },
	}
	h, err := newHandler(web.Deps{DB: pool}, allow, baseFS)
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	h.routes(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	form := url.Values{"ip": {"10.20.24.30"}, "port": {"22"}, "proto": {"tcp"}, "comment": {"z formularza"},
		"tags": {"x, y"}, "severity": {"Low"}, "return": {"/changes"}}
	resp, err := client.PostForm(srv.URL+"/annotations", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/changes" {
		t.Fatalf("save: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	form.Set("severity", "Bogus")
	resp, _ = client.PostForm(srv.URL+"/annotations", form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid severity: %d", resp.StatusCode)
	}

	for _, p := range []string{"/annotations", "/annotations/cell?ip=10.20.24.30&port=22&proto=tcp", "/changes", "/host-states", "/annotations/edit?ip=10.20.24.30&port=22&proto=tcp"} {
		resp, err := client.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		_, _ = io.Copy(&b, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("GET %s: %d %s", p, resp.StatusCode, b.String())
		}
		if strings.HasPrefix(p, "/annotations") && !strings.Contains(b.String(), "z formularza") {
			t.Errorf("GET %s: annotation missing", p)
		}
	}
	resp, _ = client.Get(srv.URL + "/changes/999")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing run: %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/annotations/delete", strings.NewReader("ip=10.20.24.30&port=22&proto=tcp"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	if _, err := store.GetAnnotation(ctx, pool, model.AssetKey{IP: ip("10.20.24.30"), Port: 22, Proto: "tcp"}); !errors.Is(err, store.ErrAnnotationNotFound) {
		t.Errorf("after delete: %v", err)
	}
	var audits int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE entity = 'annotation'`).Scan(&audits)
	if audits != 5 {
		t.Errorf("audit rows: %d", audits)
	}
}

func TestApplyRunImportScope(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	full := labRun{hosts: []string{"10.20.0.10", "10.20.1.20"}, chunks: []string{"10.20.0.0/18"},
		services: []model.ServiceObs{
			svc(0, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(0, "10.20.0.10", 22, "OpenSSH", "9.6"),
			svc(0, "10.20.1.20", 80, "Apache httpd", "2.4.62"),
		}}
	full.services[0].CPE = "cpe:/a:igor_sysoev:nginx:1.27.3"
	scan1 := insertRun(t, pool, full)
	if _, err := ApplyRun(ctx, pool, scan1, testCfg, t0); err != nil {
		t.Fatal(err)
	}

	// The import carries one host, no CPE and no version for nginx, and an
	// extra port: only the extra port is a change; nothing else is gone.
	imp := insertRun(t, pool, labRun{hosts: []string{"10.20.0.10"}, services: []model.ServiceObs{
		svc(0, "10.20.0.10", 80, "nginx", ""),
		svc(0, "10.20.0.10", 22, "OpenSSH", "9.6"),
		svc(0, "10.20.0.10", 8080, "Jetty", ""),
	}})
	if _, err := pool.Exec(ctx, `UPDATE scan_runs SET kind = 'import' WHERE id = $1`, imp); err != nil {
		t.Fatal(err)
	}
	res, err := ApplyRun(ctx, pool, imp, testCfg, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if g := fmtChanges(res.Changes); !reflect.DeepEqual(g, []string{`new 10.20.0.10:8080/tcp ""->"Jetty"`}) {
		t.Errorf("import changes: %q", g)
	}
	if res.PrevRunID != scan1 {
		t.Errorf("import baseline %d, want %d", res.PrevRunID, scan1)
	}
	hs, err := store.ListHostStates(ctx, pool, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if h.State != model.HostUp {
			t.Errorf("host %s is %s after a partial import", h.IP, h.State)
		}
	}

	// The next scan is compared with the previous scan, not the import.
	scan2 := insertRun(t, pool, full)
	res, err = ApplyRun(ctx, pool, scan2, testCfg, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.PrevRunID != scan1 || len(res.Changes) != 0 {
		t.Errorf("scan after import: prev %d (want %d), changes %q", res.PrevRunID, scan1, fmtChanges(res.Changes))
	}
}
