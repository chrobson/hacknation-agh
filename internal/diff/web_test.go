package diff

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

var baseFS = os.DirFS("../../web/templates")

func testHandler(t *testing.T, a Access) *handler {
	t.Helper()
	h, err := newHandler(web.Deps{}, a, baseFS)
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	return h
}

func TestTemplatesRender(t *testing.T) {
	h := testHandler(t, Access{})
	now := time.Now()
	k := model.AssetKey{IP: ip("10.20.0.10"), Port: 80, Proto: "tcp"}
	ann := store.Annotation{Key: k, Comment: "panel <b>admina</b>", Tags: []string{"prod", "web"}, Severity: "Medium", FalsePositive: true}
	cs := []model.Change{
		{RunID: 2, PrevRunID: 1, Kind: model.ChangeChanged, Key: k, Field: "version", Old: "1.27.3", New: "1.26.2"},
		{RunID: 2, PrevRunID: 1, Kind: model.ChangeHostDown, Key: model.AssetKey{IP: ip("10.20.60.120")}, Old: "up", New: "down"},
		{RunID: 2, PrevRunID: 1, Kind: model.ChangeUnstable, Key: model.AssetKey{IP: ip("10.20.60.120")}, Field: "flips", New: "2"},
		{RunID: 2, PrevRunID: 1, Kind: model.ChangeGone, Key: model.AssetKey{IP: ip("10.20.24.30"), Port: 23, Proto: "tcp"}, Old: "telnetd"},
	}
	cases := []struct {
		page, name string
		data       any
		want       []string
	}{
		{"index.html", "base", indexData{
			Runs:        []store.ChangeRun{{RunID: 2, PrevRunID: 1, Kind: "scan", Status: "done", Applied: true, FinishedAt: &now, Counts: map[model.ChangeKind]int{model.ChangeNew: 3}, Total: 3}},
			Kinds:       KindOrder,
			StateCounts: map[model.HostStateKind]int{model.HostUnstable: 1},
			States:      hostStates,
		}, []string{"Zmiany między przebiegami", `href="/changes/2"`, "#1", "niestabilny"}},
		{"run.html", "base", runData{
			Run: store.ChangeRun{RunID: 2, PrevRunID: 1, Applied: true}, Total: len(cs),
			Groups:  GroupChanges(cs, map[model.AssetKey]store.Annotation{k: ann}),
			CanEdit: true, Return: "/changes/2",
		}, []string{
			"Hosty, które przestały odpowiadać (1)", "Hosty niestabilne", "Zmienione usługi", "Zniknięte usługi",
			"wersja", "1.26.2", "panel &lt;b&gt;admina&lt;/b&gt;", "fałszywy alarm", "dodaj adnotację",
			"return=%2Fchanges%2F2",
		}},
		{"hosts.html", "base", hostsData{
			Hosts:  []model.HostState{{IP: ip("10.20.60.120"), State: model.HostUnstable, Flips: []model.Flip{{RunID: 1, Up: true}, {RunID: 2}, {RunID: 3, Up: true}}}},
			States: hostStates, Counts: map[model.HostStateKind]int{}, Cfg: testCfg,
		}, []string{"Stany hostów", "10.20.60.120", "niestabilny", "przebieg #2"}},
		{"annotations.html", "base", annotationsData{Items: []store.Annotation{ann}, CanEdit: false, Return: "/annotations"},
			[]string{"10.20.0.10:80/tcp", "prod"}},
		{"annotations.html", "annotation_cell", CellData{Key: k, CanEdit: true, Return: "/x"},
			[]string{`id="ann-`, "dodaj adnotację", "hx-get"}},
		{"annotation_form.html", "base", formData{Key: k, Ann: ann, Exists: true, Return: "/changes/2", Severities: severities},
			[]string{`name="comment"`, "prod, web", `value="Medium" selected`, "Usuń adnotację", "checked"}},
		{"annotation_form.html", "annotation_form", formData{Key: k, Ann: store.Annotation{Key: k}, Return: "/a", Error: "Zły tag", Severities: severities},
			[]string{"Zły tag", `hx-post="/annotations"`}},
	}
	for _, c := range cases {
		t.Run(c.page+"/"+c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.render(rec, c.page, c.name, http.StatusOK, c.data)
			body := rec.Body.String()
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, body)
			}
			for _, w := range c.want {
				if !strings.Contains(body, w) {
					t.Errorf("missing %q in:\n%s", w, body)
				}
			}
		})
	}
	// Read-only users get no edit link.
	rec := httptest.NewRecorder()
	h.render(rec, "annotations.html", "annotation_cell", 200, CellData{Key: k, Ann: &ann})
	if strings.Contains(rec.Body.String(), "/annotations/edit") {
		t.Errorf("edit link shown without results.edit")
	}
}

func TestRoutesFailClosedAndPermissions(t *testing.T) {
	// Zero Access: every route is forbidden (no DB is touched).
	r := chi.NewRouter()
	testHandler(t, Access{}).routes(r)
	for _, p := range []string{"/changes", "/changes/1", "/host-states", "/annotations", "/annotations/cell?ip=1.2.3.4", "/annotations/edit?ip=1.2.3.4"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s without auth: %d", p, rec.Code)
		}
	}

	// A reader may read but not edit.
	perms := func(have ...string) Access {
		return Access{Require: func(perm string) func(http.Handler) http.Handler {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					for _, p := range have {
						if p == perm {
							next.ServeHTTP(w, req)
							return
						}
					}
					http.Error(w, "forbidden", http.StatusForbidden)
				})
			}
		}}
	}
	r = chi.NewRouter()
	testHandler(t, perms(PermRead)).routes(r)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/annotations/edit?ip=1.2.3.4", nil),
		httptest.NewRequest(http.MethodPost, "/annotations", strings.NewReader("ip=1.2.3.4")),
		httptest.NewRequest(http.MethodPost, "/annotations/delete", strings.NewReader("ip=1.2.3.4")),
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as reader: %d", req.Method, req.URL, rec.Code)
		}
	}
	// Validation runs before the DB: bad keys are rejected with 400.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/annotations/cell?ip=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ip: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/changes/abc", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad run id: %d", rec.Code)
	}
}

func TestParseKey(t *testing.T) {
	tests := []struct {
		q       string
		want    model.AssetKey
		wantErr bool
	}{
		{"ip=10.0.0.1", model.AssetKey{IP: ip("10.0.0.1")}, false},
		{"ip=10.0.0.1&port=0&proto=", model.AssetKey{IP: ip("10.0.0.1")}, false},
		{"ip=10.0.0.1&port=443&proto=TCP&vhost=Staging.Example", model.AssetKey{IP: ip("10.0.0.1"), Port: 443, Proto: "tcp", VHost: "staging.example"}, false},
		{"ip=::ffff:10.0.0.1&port=53&proto=udp", model.AssetKey{IP: ip("10.0.0.1"), Port: 53, Proto: "udp"}, false},
		{"ip=", model.AssetKey{}, true},
		{"ip=10.0.0.1&port=70000&proto=tcp", model.AssetKey{}, true},
		{"ip=10.0.0.1&port=80", model.AssetKey{}, true},
		{"ip=10.0.0.1&port=80&proto=sctp", model.AssetKey{}, true},
		{"ip=10.0.0.1&proto=tcp", model.AssetKey{}, true},
		{"ip=10.0.0.1&port=80&proto=tcp&vhost=a%20b", model.AssetKey{}, true},
	}
	for _, tt := range tests {
		v, _ := url.ParseQuery(tt.q)
		got, err := ParseKey(v)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: err %v", tt.q, err)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("%s: got %+v want %+v", tt.q, got, tt.want)
		}
	}
}

func TestParseAnnotation(t *testing.T) {
	k := model.AssetKey{IP: ip("10.0.0.1")}
	v := url.Values{"comment": {" hello\r\nworld "}, "tags": {"a, b,,a , c"}, "severity": {"High"}, "false_positive": {"1"}}
	a, err := ParseAnnotation(k, v)
	if err != nil {
		t.Fatal(err)
	}
	if a.Comment != "hello\nworld" || strings.Join(a.Tags, "|") != "a|b|c" || a.Severity != "High" || !a.FalsePositive {
		t.Errorf("parsed %+v", a)
	}
	bad := []url.Values{
		{"severity": {"Severe"}},
		{"comment": {strings.Repeat("x", maxComment+1)}},
		{"tags": {manyTags(maxTags + 1)}},
		{"tags": {strings.Repeat("x", maxTagLen+1)}},
	}
	for _, b := range bad {
		if _, err := ParseAnnotation(k, b); err == nil {
			t.Errorf("accepted %v", b)
		}
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "/annotations",
		"/changes/2?x=1":    "/changes/2?x=1",
		"//evil.example":    "/annotations",
		"/\\evil.example":   "/annotations",
		"https://evil.test": "/annotations",
		"/a\r\nLocation: x": "/annotations",
		"/\t/evil.example":  "/annotations",
		"/a\\b":             "/annotations",
		"/annotations?ip=1": "/annotations?ip=1",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func manyTags(n int) string {
	tags := make([]string, n)
	for i := range tags {
		tags[i] = "t" + strconv.Itoa(i)
	}
	return strings.Join(tags, ",")
}

func TestFallbackBaseAndEmbeddedTemplates(t *testing.T) {
	h, err := newHandler(web.Deps{}, Access{}, nil)
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	rec := httptest.NewRecorder()
	h.render(rec, "index.html", "base", http.StatusOK, indexData{Kinds: KindOrder, States: hostStates})
	if body := rec.Body.String(); !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "Zmiany między przebiegami") {
		t.Errorf("fallback layout not rendered:\n%s", body)
	}
}

func TestCellTargetsClosest(t *testing.T) {
	// One key can appear in several rows of a run page, so htmx must not
	// target the cell by id.
	h := testHandler(t, Access{})
	k := model.AssetKey{IP: ip("10.20.0.10"), Port: 22, Proto: "tcp"}
	rec := httptest.NewRecorder()
	h.render(rec, "annotations.html", "annotation_cell", http.StatusOK, CellData{Key: k, CanEdit: true, Return: "/changes/2"})
	if body := rec.Body.String(); !strings.Contains(body, `hx-target="closest .annotation"`) {
		t.Errorf("cell does not target closest .annotation:\n%s", body)
	}
}
