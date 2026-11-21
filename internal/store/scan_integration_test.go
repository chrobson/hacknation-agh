//go:build integration

package store_test

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// Requires an empty database: ASI_TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/store/
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
	return pool
}

func TestScanStoreLifecycle(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	s := store.NewScanStore(pool)

	var targetID, cfgID int64
	if err := pool.QueryRow(ctx, `INSERT INTO targets (kind, value) VALUES ('cidr', '10.20.0.0/23')
		ON CONFLICT (value) DO UPDATE SET kind=EXCLUDED.kind RETURNING id`).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	name := "it-" + time.Now().Format("150405.000000")
	if err := pool.QueryRow(ctx, `INSERT INTO scan_configs (name, target_ids, window_start, window_end, every_minutes)
		VALUES ($1, $2, '22:00', '06:30', 60) RETURNING id`, name, []int64{targetID}).Scan(&cfgID); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Config(ctx, cfgID)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasWindow() || *cfg.WindowStart != 22*time.Hour || *cfg.WindowEnd != 6*time.Hour+30*time.Minute || *cfg.EveryMinutes != 60 {
		t.Fatalf("config = %+v", cfg)
	}
	ts, err := s.TargetsByIDs(ctx, cfg.TargetIDs)
	if err != nil || len(ts) != 1 || ts[0].Kind != model.TargetCIDR {
		t.Fatalf("targets = %+v err=%v", ts, err)
	}

	chunks := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.20.1.0/24"), netip.MustParsePrefix("10.20.2.5/32")}
	runID, err := s.CreateRun(ctx, &cfgID, chunks)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartRun(ctx, runID); err != nil {
		t.Fatal(err)
	}

	// Concurrent leases never return the same chunk.
	var mu sync.Mutex
	seen := map[int64]store.Chunk{}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, ok, err := s.LeaseChunk(ctx, runID)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				if _, dup := seen[c.ID]; dup {
					t.Errorf("chunk %d leased twice", c.ID)
				}
				seen[c.ID] = c
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 3 {
		t.Fatalf("leased %d chunks, want 3", len(seen))
	}

	// Crash: everything back to pending, run paused.
	if n, err := s.ResetRunning(ctx); err != nil || n < 3 {
		t.Fatalf("ResetRunning = %d, %v", n, err)
	}
	open, err := s.OpenRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range open {
		if o.ID == runID {
			found = o.Status == store.RunPaused
		}
	}
	if !found {
		t.Fatalf("run %d not paused in %+v", runID, open)
	}

	ip := netip.MustParseAddr("10.20.0.10")
	for {
		c, ok, err := s.LeaseChunk(ctx, runID)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if c.Attempts != 2 {
			t.Errorf("attempts = %d, want 2", c.Attempts)
		}
		switch c.Prefix.String() {
		case "10.20.0.0/24":
			hosts := []model.HostObs{{IP: ip, Up: true}}
			svcs := []model.ServiceObs{{Key: model.AssetKey{IP: ip, Port: 80, Proto: "tcp"}, Product: "nginx", Version: "1.27.3", Banner: "http"}}
			if err := s.CompleteChunk(ctx, c, 1500*time.Millisecond, hosts, svcs); err != nil {
				t.Fatal(err)
			}
			// Idempotent per natural key.
			tx, _ := pool.Begin(ctx)
			if err := store.InsertObservations(ctx, tx, runID, hosts, svcs); err != nil {
				t.Fatal(err)
			}
			_ = tx.Commit(ctx)
		case "10.20.1.0/24":
			if err := s.ReleaseChunk(ctx, c.ID, "przerwano"); err != nil {
				t.Fatal(err)
			}
			c2, ok, _ := s.LeaseChunk(ctx, runID)
			if !ok || c2.ID != c.ID {
				t.Fatalf("released chunk not leased again: %+v", c2)
			}
			// An interruption refunds the lease's attempt.
			if err := s.InterruptChunk(ctx, c.ID, "koniec okna"); err != nil {
				t.Fatal(err)
			}
			c3, ok, _ := s.LeaseChunk(ctx, runID)
			if !ok || c3.ID != c.ID || c3.Attempts != c2.Attempts {
				t.Fatalf("interrupted chunk: %+v, want attempts %d", c3, c2.Attempts)
			}
			if err := s.FailChunk(ctx, c.ID, "nmap exit 1"); err != nil {
				t.Fatal(err)
			}
		default:
			if err := s.CompleteChunk(ctx, c, time.Second, []model.HostObs{{IP: c.Prefix.Addr(), Up: false}}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	counts, err := s.CountChunks(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if counts != (store.ChunkCounts{Done: 2, Failed: 1}) {
		t.Fatalf("counts = %+v", counts)
	}
	if err := s.FinishRun(ctx, runID, store.RunDone, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	var status string
	var dur int64
	var finished *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, duration_ms, finished_at FROM scan_runs WHERE id=$1`, runID).Scan(&status, &dur, &finished); err != nil {
		t.Fatal(err)
	}
	if status != "done" || dur != 2000 || finished == nil {
		t.Errorf("run = %s %d %v", status, dur, finished)
	}
	var hostsUp, chunkDur int64
	if err := pool.QueryRow(ctx, `SELECT hosts_up, duration_ms FROM scan_chunks WHERE run_id=$1 AND cidr='10.20.0.0/24'`, runID).Scan(&hostsUp, &chunkDur); err != nil {
		t.Fatal(err)
	}
	if hostsUp != 1 || chunkDur != 1500 {
		t.Errorf("chunk hosts_up=%d duration_ms=%d", hostsUp, chunkDur)
	}
	var nSvc, nHost int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM services WHERE run_id=$1`, runID).Scan(&nSvc)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM host_obs WHERE run_id=$1`, runID).Scan(&nHost)
	if nSvc != 1 || nHost != 2 {
		t.Errorf("services=%d host_obs=%d", nSvc, nHost)
	}
	last, err := s.LastRun(ctx, cfgID)
	if err != nil || last == nil || last.ID != runID || last.StartedAt == nil {
		t.Errorf("LastRun = %+v, %v", last, err)
	}
}
