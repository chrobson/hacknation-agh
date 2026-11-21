//go:build integration

package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/web"
)

func TestMountPostgres(t *testing.T) {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM targets WHERE value IN ('10.20.0.0/24', '10.20.1.10')`)
	}
	cleanup()
	defer cleanup()

	r := chi.NewRouter()
	prev := Authz
	Authz = AllowAll
	t.Cleanup(func() { Authz = prev })
	Mount(r, web.Deps{DB: pool, Config: config.Config{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")}}})
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Authz is AllowAll here; permissions are covered by unit tests.
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "import", "targets.csv"))
	if err != nil {
		t.Fatal(err)
	}
	// Drop the public domain row: Mount uses the real resolver and tests must
	// not send DNS queries.
	data = data[:len(data)-len("scanme.nmap.org,external\n")]
	req := upload(t, srv, "targets.csv", data)
	req.Header.Set("Accept", "application/json")
	resp, body := do(t, req, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: %d %s", resp.StatusCode, body)
	}
	var rep Report
	_ = json.Unmarshal([]byte(body), &rep)
	if rep.Imported != 2 || rep.Duplicates != 0 || len(rep.Errors) != 0 {
		t.Fatalf("report %+v", rep)
	}
	get, _ := http.NewRequest(http.MethodGet, srv.URL+"/targets", nil)
	if resp, body := do(t, get, ""); resp.StatusCode != http.StatusOK || !strings.Contains(body, "10.20.1.10") {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var audits int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'targets.import'`).Scan(&audits)
	if audits == 0 {
		t.Error("no audit row")
	}
}
