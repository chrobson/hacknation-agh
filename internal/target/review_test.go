package target

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestNilAuthorizerFailsClosed(t *testing.T) {
	h, err := NewHandler(&memStore{}, testImporter(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	h.Routes(r)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/targets"},
		{http.MethodGet, "/targets/export"},
		{http.MethodPost, "/targets"},
		{http.MethodPost, "/targets/upload"},
		{http.MethodPost, "/targets/1/delete"},
		{http.MethodDelete, "/targets/1"},
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
}

func TestNormalizeTagsRejectsFormulaPrefix(t *testing.T) {
	for _, tag := range []string{"=cmd|' /c calc'!A0", "+1", "-x", "@sum(a1)"} {
		if _, err := NormalizeTags([]string{tag}); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
	}
	if _, err := NormalizeTags([]string{"a-b", "x=y"}); err != nil {
		t.Errorf("inner characters rejected: %v", err)
	}
}

// nameResolver maps every name to an address inside the allowlist.
type nameResolver struct{}

func (nameResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var n int
	if _, err := fmt.Sscanf(host, "h%d.lab.example", &n); err != nil {
		return nil, fmt.Errorf("no such host")
	}
	return []netip.Addr{netip.AddrFrom4([4]byte{10, 20, 0, byte(n)})}, nil
}

func TestPrepareConcurrentKeepsOrder(t *testing.T) {
	im := Importer{Allow: NewAllowlist([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")}), Resolver: nameResolver{}}
	var es []Entry
	for i := 0; i < 100; i++ {
		es = append(es, Entry{Line: i + 1, Value: fmt.Sprintf("h%d.lab.example", i)})
	}
	es = append(es, Entry{Line: 101, Value: "bad.other"}, Entry{Line: 102, Value: "10.20.0.0/24"})
	ts, rep := im.Prepare(context.Background(), es)
	if len(ts) != 101 || len(rep.Errors) != 1 || rep.Errors[0].Line != 101 {
		t.Fatalf("got %d targets, errors %+v", len(ts), rep.Errors)
	}
	for i := 0; i < 100; i++ {
		if want := fmt.Sprintf("h%d.lab.example", i); ts[i].Value != want {
			t.Fatalf("ts[%d] = %s, want %s", i, ts[i].Value, want)
		}
	}
}

func TestTagFilterNormalized(t *testing.T) {
	srv, st := newTestServer(t)
	st.rows = append(st.rows,
		model.Target{ID: 1, Kind: model.TargetIP, Value: "10.20.0.1", Tags: []string{"lab"}},
		model.Target{ID: 2, Kind: model.TargetIP, Value: "10.20.0.2", Tags: []string{"web"}})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/targets/export?format=csv&tag=%20LAB%20", nil)
	resp, body := do(t, req, PermRead)
	if resp.StatusCode != http.StatusOK || body != "value,tags\n10.20.0.1,lab\n" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}
