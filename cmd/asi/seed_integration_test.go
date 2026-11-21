//go:build integration

package main

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/db"
)

// ASI_TEST_DATABASE_URL=postgres://... go test -tags integration ./cmd/asi/
func TestSeedDemo(t *testing.T) {
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
	cfg := config.Config{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, MaxRate: 5000}

	res, err := seedDemo(ctx, pool, cfg, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ConfigID == 0 || res.MaxRate != 1000 || res.Profile != "auto" {
		t.Fatalf("result: %+v", res)
	}
	again, err := seedDemo(ctx, pool, cfg, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if again.ConfigID != res.ConfigID || again.Imported != 0 {
		t.Fatalf("not idempotent: %+v vs %+v", again, res)
	}
	var profile string
	var rate, workers int
	var every *int
	var targets []string
	if err := pool.QueryRow(ctx, `SELECT c.port_profile, c.max_rate, c.workers, c.every_minutes,
		ARRAY(SELECT t.value FROM targets t WHERE t.id = ANY(c.target_ids))
		FROM scan_configs c WHERE c.id=$1`, res.ConfigID).Scan(&profile, &rate, &workers, &every, &targets); err != nil {
		t.Fatal(err)
	}
	if profile != "auto" || rate != 1000 || workers != 4 || every != nil || strings.Join(targets, ",") != "127.0.0.1" {
		t.Fatalf("config: %s %d %d %v %v", profile, rate, workers, every, targets)
	}

	if _, err := seedDemo(ctx, pool, cfg, []string{"8.8.8.8"}); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("target outside the allowlist accepted: %v", err)
	}
}
