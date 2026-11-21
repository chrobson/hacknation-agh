package dojo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeDojo emulates the three DefectDojo API v2 endpoints ASI uses.
type fakeDojo struct {
	mu        sync.Mutex
	calls     []string
	forms     map[string]map[string]string
	files     map[string][]byte
	testExist bool
}

func newFakeDojo(t *testing.T, testExists bool) (*fakeDojo, *httptest.Server) {
	f := &fakeDojo{forms: map[string]map[string]string{}, files: map[string][]byte{}, testExist: testExists}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/api-token-auth/", func(w http.ResponseWriter, r *http.Request) {
		f.record("auth")
		var in struct{ Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username != "admin" || in.Password != "s3cret" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"non_field_errors":["Unable to log in"]}`)
			return
		}
		_, _ = io.WriteString(w, `{"token":"tok123"}`)
	})
	upload := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.record(name)
			if r.Header.Get("Authorization") != "Token tok123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("%s: multipart: %v", name, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			form := map[string]string{}
			for k, v := range r.MultipartForm.Value {
				form[k] = v[0]
			}
			file, _, err := r.FormFile("file")
			if err != nil {
				t.Errorf("%s: no file: %v", name, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(file)
			f.mu.Lock()
			f.forms[name], f.files[name] = form, body
			exists := f.testExist
			f.mu.Unlock()
			if name == "reimport" && !exists && form["test"] == "" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"message":"Test not found"}`)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"test":42,"test_id":42,"engagement_id":3,"product_id":2,"statistics":{"after":{"info":{"active":5}}}}`)
		}
	}
	mux.HandleFunc("POST /api/v2/import-scan/", upload("import"))
	mux.HandleFunc("POST /api/v2/reimport-scan/", upload("reimport"))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeDojo) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func goldenFile(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdataDir, "golden_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestClientImportThenReimport(t *testing.T) {
	fake, srv := newFakeDojo(t, false)
	c := &Client{BaseURL: srv.URL + "/", Username: "admin", Password: "s3cret", HTTP: srv.Client()}
	ctx := context.Background()
	if err := c.Authenticate(ctx); err != nil {
		t.Fatal(err)
	}
	if c.Token != "tok123" {
		t.Fatalf("token %q", c.Token)
	}
	file := goldenFile(t)
	p := PushParams{Product: "ASI lab", Engagement: "e2e"}
	r1, err := c.ImportScan(ctx, p, file)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ID() != 42 || r1.Endpoint != "import-scan" || len(r1.Statistics) == 0 {
		t.Errorf("import result %+v", r1)
	}
	p.TestID = r1.ID()
	if _, err := c.ReimportScan(ctx, p, file); err != nil {
		t.Fatal(err)
	}
	imp, re := fake.forms["import"], fake.forms["reimport"]
	for k, want := range map[string]string{
		"scan_type": ScanType, "auto_create_context": "true", "product_name": "ASI lab",
		"engagement_name": "e2e", "product_type_name": "ASI", "close_old_findings": "false",
	} {
		if imp[k] != want {
			t.Errorf("import %s=%q, want %q", k, imp[k], want)
		}
	}
	for k, want := range map[string]string{
		"scan_type": ScanType, "close_old_findings": "true", "test": "42", "auto_create_context": "true",
	} {
		if re[k] != want {
			t.Errorf("reimport %s=%q, want %q", k, re[k], want)
		}
	}
	if string(fake.files["reimport"]) != string(file) {
		t.Error("uploaded file differs")
	}
}

func TestClientPushFallsBackToImport(t *testing.T) {
	fake, srv := newFakeDojo(t, false)
	c := &Client{BaseURL: srv.URL, Username: "admin", Password: "s3cret", HTTP: srv.Client()}
	r, err := c.Push(context.Background(), PushParams{}, goldenFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Endpoint != "import-scan" {
		t.Errorf("endpoint %q", r.Endpoint)
	}
	want := []string{"auth", "reimport", "import"}
	if len(fake.calls) != 3 || fake.calls[0] != want[0] || fake.calls[1] != want[1] || fake.calls[2] != want[2] {
		t.Errorf("calls %v, want %v", fake.calls, want)
	}
}

func TestClientPushReimportsExistingTest(t *testing.T) {
	fake, srv := newFakeDojo(t, true)
	c := &Client{BaseURL: srv.URL, Token: "tok123", HTTP: srv.Client()}
	r, err := c.Push(context.Background(), PushParams{}, goldenFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Endpoint != "reimport-scan" || len(fake.calls) != 1 {
		t.Errorf("endpoint %q calls %v", r.Endpoint, fake.calls)
	}
	if fake.forms["reimport"]["close_old_findings"] != "true" {
		t.Error("close_old_findings not set")
	}
}

func TestClientErrors(t *testing.T) {
	_, srv := newFakeDojo(t, true)
	ctx := context.Background()
	bad := &Client{BaseURL: srv.URL, Username: "admin", Password: "wrong", HTTP: srv.Client()}
	err := bad.Authenticate(ctx)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest {
		t.Errorf("bad credentials: %v", err)
	}
	if err := (&Client{BaseURL: srv.URL}).Authenticate(ctx); err == nil {
		t.Error("no credentials accepted")
	}
	wrongTok := &Client{BaseURL: srv.URL, Token: "nope", HTTP: srv.Client()}
	if _, err := wrongTok.ImportScan(ctx, PushParams{}, goldenFile(t)); !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Errorf("wrong token: %v", err)
	}
	if _, err := (&Client{BaseURL: srv.URL, Token: "tok123"}).Push(ctx, PushParams{}, []byte(`{"findings":[{"title":"x"}]}`)); err == nil {
		t.Error("invalid file pushed")
	}
	if _, err := (&Client{BaseURL: "ftp://x", Token: "t"}).ImportScan(ctx, PushParams{}, nil); err == nil {
		t.Error("non-http URL accepted")
	}
}
