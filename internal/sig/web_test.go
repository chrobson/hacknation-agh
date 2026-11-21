package sig

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

type memStore struct {
	mu   sync.Mutex
	rows map[string]SignatureRow
}

func newMemStore(t *testing.T) *memStore {
	sigs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	m := &memStore{rows: map[string]SignatureRow{}}
	for _, s := range sigs[:3] {
		m.rows[s.ID] = SignatureRow{ID: s.ID, Name: s.Name, YAML: s.Raw, Enabled: true, Builtin: true}
	}
	return m
}

func (m *memStore) List(context.Context) ([]SignatureRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SignatureRow
	for _, r := range m.rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *memStore) Get(_ context.Context, id string) (SignatureRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return r, ErrNotFound
	}
	return r, nil
}

func (m *memStore) Create(_ context.Context, s *Signature) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[s.ID]; ok {
		return fmt.Errorf("exists")
	}
	m.rows[s.ID] = SignatureRow{ID: s.ID, Name: s.Name, YAML: s.Raw, Enabled: true}
	return nil
}

func (m *memStore) Update(_ context.Context, id string, s *Signature) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return ErrNotFound
	}
	if r.Builtin {
		return ErrBuiltin
	}
	r.Name, r.YAML = s.Name, s.Raw
	m.rows[id] = r
	return nil
}

func (m *memStore) SetEnabled(_ context.Context, id string, en bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return ErrNotFound
	}
	r.Enabled = en
	m.rows[id] = r
	return nil
}

func (m *memStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return ErrNotFound
	}
	if r.Builtin {
		return ErrBuiltin
	}
	delete(m.rows, id)
	return nil
}

// permAuth grants the permissions listed in the X-Test-Perms header.
func permAuth(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("X-Test-Perms"), perm) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func setupWeb(t *testing.T, auth func(string) func(http.Handler) http.Handler) (*httptest.Server, *memStore, *int) {
	t.Helper()
	prevA, prevT, prevC := Authorize, TemplateFS, OnChange
	t.Cleanup(func() { Authorize, TemplateFS, OnChange = prevA, prevT, prevC })
	Authorize = auth
	TemplateFS = os.DirFS("../../web/templates")
	changes := 0
	OnChange = func(context.Context) { changes++ }
	st := newMemStore(t)
	r := chi.NewRouter()
	MountStore(r, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, st, &changes
}

func do(t *testing.T, srv *httptest.Server, method, path, perms string, form url.Values) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("X-Test-Perms", perms)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const customYAML = `id: custom-app
name: Moja aplikacja
category: framework
confidence: 70
matchers:
  - {type: header, name: X-App, regex: 'MyApp'}
`

func TestWebFailsClosedWithoutAuthorize(t *testing.T) {
	srv, _, _ := setupWeb(t, nil)
	for _, p := range []string{"/signatures", "/signatures/new", "/signatures/wordpress"} {
		if code, _ := do(t, srv, "GET", p, "", nil); code != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", p, code)
		}
	}
}

func TestWebListAndPermissions(t *testing.T) {
	srv, st, changes := setupWeb(t, permAuth)
	code, body := do(t, srv, "GET", "/signatures", "results.read", nil)
	if code != 200 || !strings.Contains(body, "Sygnatury detekcyjne") || !strings.Contains(body, "admin-panel") {
		t.Fatalf("list: %d\n%s", code, body)
	}
	if !strings.Contains(body, "<html") {
		t.Fatal("base layout not rendered")
	}
	// Reader cannot create.
	if code, _ := do(t, srv, "POST", "/signatures", "results.read", url.Values{"yaml": {customYAML}}); code != 403 {
		t.Fatalf("reader create = %d", code)
	}
	if code, _ := do(t, srv, "GET", "/signatures/new", "results.read", nil); code != 403 {
		t.Fatalf("reader new form = %d", code)
	}
	w := "results.read signatures.write"
	if code, body := do(t, srv, "GET", "/signatures/new", w, nil); code != 200 || !strings.Contains(body, "textarea") {
		t.Fatalf("new form: %d", code)
	}
	// Invalid: POST method in a path probe.
	bad := strings.Replace(customYAML, "  - {type: header, name: X-App, regex: 'MyApp'}", "  - {type: path, path: /x, method: POST, status: [200]}", 1)
	code, body = do(t, srv, "POST", "/signatures", w, url.Values{"yaml": {bad}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "only GET or HEAD") {
		t.Fatalf("invalid create: %d\n%s", code, body)
	}
	if _, err := st.Get(context.Background(), "custom-app"); err == nil {
		t.Fatal("invalid signature stored")
	}
	// Valid.
	if code, _ := do(t, srv, "POST", "/signatures", w, url.Values{"yaml": {customYAML}}); code != http.StatusSeeOther {
		t.Fatalf("create = %d", code)
	}
	if _, err := st.Get(context.Background(), "custom-app"); err != nil {
		t.Fatal(err)
	}
	// Duplicate id.
	if code, body := do(t, srv, "POST", "/signatures", w, url.Values{"yaml": {customYAML}}); code != 422 || !strings.Contains(body, "już istnieje") {
		t.Fatalf("duplicate = %d", code)
	}
	// View and edit.
	if code, body := do(t, srv, "GET", "/signatures/custom-app", "results.read", nil); code != 200 || !strings.Contains(body, "X-App") {
		t.Fatalf("view = %d", code)
	}
	edited := strings.Replace(customYAML, "confidence: 70", "confidence: 80", 1)
	if code, _ := do(t, srv, "POST", "/signatures/custom-app", w, url.Values{"yaml": {edited}}); code != 303 {
		t.Fatalf("update = %d", code)
	}
	if r, _ := st.Get(context.Background(), "custom-app"); !strings.Contains(r.YAML, "confidence: 80") {
		t.Fatal("update not stored")
	}
	renamed := strings.Replace(customYAML, "id: custom-app", "id: other-id", 1)
	if code, _ := do(t, srv, "POST", "/signatures/custom-app", w, url.Values{"yaml": {renamed}}); code != 422 {
		t.Fatalf("id change = %d", code)
	}
	// Built-ins are read-only but can be toggled.
	builtin := ""
	for id, r := range st.rows {
		if r.Builtin {
			builtin = id
			break
		}
	}
	if code, _ := do(t, srv, "GET", "/signatures/"+builtin+"/edit", w, nil); code != http.StatusConflict {
		t.Fatalf("edit builtin = %d", code)
	}
	if code, _ := do(t, srv, "POST", "/signatures/"+builtin+"/delete", w, url.Values{}); code != http.StatusConflict {
		t.Fatalf("delete builtin = %d", code)
	}
	if code, _ := do(t, srv, "POST", "/signatures/"+builtin+"/toggle", w, url.Values{}); code != 303 {
		t.Fatalf("toggle = %d", code)
	}
	if r, _ := st.Get(context.Background(), builtin); r.Enabled {
		t.Fatal("toggle did not disable")
	}
	if code, _ := do(t, srv, "POST", "/signatures/custom-app/delete", w, url.Values{}); code != 303 {
		t.Fatalf("delete = %d", code)
	}
	if code, _ := do(t, srv, "GET", "/signatures/nope", "results.read", nil); code != 404 {
		t.Fatalf("missing = %d", code)
	}
	if *changes != 4 {
		t.Fatalf("OnChange called %d times, want 4", *changes)
	}
}

func TestWebValidateFragment(t *testing.T) {
	srv, _, _ := setupWeb(t, permAuth)
	w := "signatures.write"
	code, body := do(t, srv, "POST", "/signatures/validate", w, url.Values{"yaml": {customYAML}})
	if code != 200 || !strings.Contains(body, "Sygnatura poprawna") || strings.Contains(body, "<html") {
		t.Fatalf("validate ok: %d\n%s", code, body)
	}
	_, body = do(t, srv, "POST", "/signatures/validate", w, url.Values{"yaml": {customYAML + "    headers: {Authorization: x}\n"}})
	if !strings.Contains(body, "Błędy walidacji") {
		t.Fatalf("validate bad:\n%s", body)
	}
}

func TestWebFlashOnlyFixedMessages(t *testing.T) {
	srv, _, _ := setupWeb(t, permAuth)
	_, body := do(t, srv, "GET", "/signatures?msg=deleted", "results.read", nil)
	if !strings.Contains(body, "Usunięto sygnaturę.") {
		t.Fatalf("known flash code not rendered")
	}
	_, body = do(t, srv, "GET", "/signatures?msg=Zadzwon+pod+123", "results.read", nil)
	if strings.Contains(body, "Zadzwon") || strings.Contains(body, `class="flash"`) {
		t.Fatalf("arbitrary ?msg= text reflected")
	}
}

func TestWebRejectsOversizedForm(t *testing.T) {
	srv, st, _ := setupWeb(t, permAuth)
	big := customYAML + "description: " + strings.Repeat("x", MaxYAMLBytes+8192) + "\n"
	code, body := do(t, srv, "POST", "/signatures", "signatures.write", url.Values{"yaml": {big}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "za duży") {
		t.Fatalf("oversized: %d", code)
	}
	if _, err := st.Get(context.Background(), "custom-app"); err == nil {
		t.Fatal("oversized signature was stored")
	}
}
