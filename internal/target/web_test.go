package target

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/model"
)

type memStore struct {
	mu     sync.Mutex
	next   int64
	rows   []model.Target
	audits []string
}

func (m *memStore) List(_ context.Context, tag string) ([]model.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Target
	for _, t := range m.rows {
		if tag == "" || slices.Contains(t.Tags, tag) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *memStore) Tags(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, t := range m.rows {
		for _, g := range t.Tags {
			if !slices.Contains(out, g) {
				out = append(out, g)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func (m *memStore) Insert(_ context.Context, ts []model.Target, _ *int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range ts {
		if slices.ContainsFunc(m.rows, func(r model.Target) bool { return r.Value == t.Value }) {
			continue
		}
		m.next++
		t.ID = m.next
		m.rows = append(m.rows, t)
		n++
	}
	m.audits = append(m.audits, "import")
	return n, nil
}

func (m *memStore) UpdateTags(_ context.Context, id int64, tags []string, _ *int64) (model.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rows {
		if m.rows[i].ID == id {
			m.rows[i].Tags = tags
			return m.rows[i], nil
		}
	}
	return model.Target{}, ErrNotFound
}

func (m *memStore) Delete(_ context.Context, id int64, _ *int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rows {
		if m.rows[i].ID == id {
			m.rows = slices.Delete(m.rows, i, i+1)
			return nil
		}
	}
	return ErrNotFound
}

// permAuth grants the permissions listed in the X-Test-Perms header.
type permAuth struct{}

func (permAuth) Allowed(r *http.Request, perm string) bool {
	return slices.Contains(strings.Split(r.Header.Get("X-Test-Perms"), ","), perm)
}
func (permAuth) UserID(*http.Request) (int64, bool) { return 1, true }

func newTestServer(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	st := &memStore{}
	h, err := NewHandler(st, testImporter(), permAuth{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	h.Routes(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, st
}

func do(t *testing.T, req *http.Request, perms string) (*http.Response, string) {
	t.Helper()
	req.Header.Set("X-Test-Perms", perms)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const rw = PermRead + "," + PermWrite

func postForm(srv *httptest.Server, path string, v url.Values) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestWebPermissions(t *testing.T) {
	srv, _ := newTestServer(t)
	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/targets", nil)
	if resp, _ := do(t, get, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET without targets.read: %d", resp.StatusCode)
	}
	get, _ = http.NewRequest(http.MethodGet, srv.URL+"/targets", nil)
	resp, body := do(t, get, PermRead)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Cele skanowania") {
		t.Fatalf("GET with read: %d", resp.StatusCode)
	}
	if strings.Contains(body, "Dodaj ręcznie") {
		t.Error("read-only user must not see the add form")
	}
	add := postForm(srv, "/targets", url.Values{"values": {"10.20.0.1"}})
	if resp, _ := do(t, add, PermRead); resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without targets.write: %d", resp.StatusCode)
	}
	del, _ := http.NewRequest(http.MethodPost, srv.URL+"/targets/1/delete", nil)
	if resp, _ := do(t, del, PermRead); resp.StatusCode != http.StatusForbidden {
		t.Errorf("delete without targets.write: %d", resp.StatusCode)
	}
}

func TestWebAddListDelete(t *testing.T) {
	srv, st := newTestServer(t)
	add := postForm(srv, "/targets", url.Values{
		"values": {"10.20.0.0/24 web\n10.20.1.10\n10.20.1.10/32\n8.8.8.8\nscanme.nmap.org"},
		"tags":   {"lab"},
	})
	resp, body := do(t, add, rw)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add: %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{"Zaimportowano: <strong>2</strong>", "duplikaty: <strong>1</strong>", "błędy: <strong>2</strong>", "poza dozwolonymi sieciami", "<!doctype html>"} {
		if !strings.Contains(body, want) {
			t.Errorf("add response lacks %q", want)
		}
	}
	if len(st.rows) != 2 || strings.Join(st.rows[0].Tags, ";") != "lab;web" {
		t.Fatalf("rows = %+v", st.rows)
	}

	// htmx request gets only the fragment.
	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/targets?tag=web", nil)
	get.Header.Set("HX-Request", "true")
	_, body = do(t, get, PermRead)
	if strings.Contains(body, "<!doctype html>") || !strings.Contains(body, `id="targets-page"`) {
		t.Error("htmx GET should return the page fragment only")
	}
	if !strings.Contains(body, "10.20.0.0/24") || strings.Contains(body, "<code>10.20.1.10</code>") {
		t.Error("tag filter not applied")
	}

	// Edit tags (htmx returns the row).
	ed := postForm(srv, "/targets/2/tags", url.Values{"tags": {"Core; dmz"}})
	ed.Header.Set("HX-Request", "true")
	resp, body = do(t, ed, rw)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="target-2"`) || !strings.Contains(body, `value="core;dmz"`) {
		t.Errorf("tags edit: %d %s", resp.StatusCode, body)
	}

	del, _ := http.NewRequest(http.MethodPost, srv.URL+"/targets/1/delete", nil)
	resp, _ = do(t, del, rw)
	if resp.StatusCode != http.StatusSeeOther || len(st.rows) != 1 {
		t.Errorf("delete: %d rows=%d", resp.StatusCode, len(st.rows))
	}
	bad, _ := http.NewRequest(http.MethodDelete, srv.URL+"/targets/abc", nil)
	if resp, _ := do(t, bad, rw); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad id: %d", resp.StatusCode)
	}
}

func upload(t *testing.T, srv *httptest.Server, name string, data []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write(data)
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/targets/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestWebUploadFixturesJSONReport(t *testing.T) {
	want := loadExpectedReport(t)
	for _, name := range []string{"targets.csv", "targets.json"} {
		srv, st := newTestServer(t)
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "import", name))
		if err != nil {
			t.Fatal(err)
		}
		req := upload(t, srv, name, data)
		req.Header.Set("Accept", "application/json")
		resp, body := do(t, req, rw)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, body)
		}
		var got Report
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if got.Imported != want.Imported || got.Duplicates != want.Duplicates || len(got.Errors) != 1 || got.Errors[0] != want.Errors[0] {
			t.Errorf("%s: report %+v, want %+v", name, got, want)
		}
		// Second upload: everything already there.
		req = upload(t, srv, name, data)
		req.Header.Set("Accept", "application/json")
		_, body = do(t, req, rw)
		_ = json.Unmarshal([]byte(body), &got)
		if got.Imported != 0 || got.Duplicates != 2 {
			t.Errorf("%s: re-import %+v", name, got)
		}
		if len(st.rows) != 2 {
			t.Errorf("%s: rows %d", name, len(st.rows))
		}

		// Export both formats.
		for _, f := range []string{"csv", "json"} {
			ex, _ := http.NewRequest(http.MethodGet, srv.URL+"/targets/export?format="+f, nil)
			resp, body := do(t, ex, PermRead)
			if resp.StatusCode != http.StatusOK || !strings.Contains(body, "10.20.0.0/24") || !strings.Contains(resp.Header.Get("Content-Disposition"), "targets."+f) {
				t.Errorf("export %s: %d %s", f, resp.StatusCode, body)
			}
		}
	}
}

func TestWebUploadErrors(t *testing.T) {
	srv, _ := newTestServer(t)
	req := upload(t, srv, "x.json", []byte(`{"not":"array"}`))
	req.Header.Set("HX-Request", "true")
	resp, body := do(t, req, rw)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Nie udało się odczytać pliku") {
		t.Errorf("bad json via htmx: %d %s", resp.StatusCode, body)
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/targets/upload", strings.NewReader(""))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	if resp, _ := do(t, req, rw); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing file: %d", resp.StatusCode)
	}
}

func TestErrLabel(t *testing.T) {
	if got := errLabel(ErrNotAllowed.Error()); got != "poza dozwolonymi sieciami (allowlista)" {
		t.Errorf("got %q", got)
	}
	if got := errLabel("resolve x.test: no such host"); !strings.HasPrefix(got, "nie udało się rozwiązać") {
		t.Errorf("got %q", got)
	}
	if got := errLabel("something else"); got != "something else" {
		t.Errorf("got %q", got)
	}
}

func TestMountTemplatesParse(t *testing.T) {
	if _, err := ParseTemplates(); err != nil {
		t.Fatal(err)
	}
	BaseTemplates = os.DirFS(filepath.Join("..", "..", "web", "templates"))
	defer func() { BaseTemplates = nil }()
	if _, err := ParseTemplates(); err != nil {
		t.Fatalf("with shared base.html: %v", err)
	}
}
