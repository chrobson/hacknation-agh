package runner

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/target"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func labAllow() target.Allowlist {
	return target.NewAllowlist([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")})
}

func setup(t *testing.T, targets ...model.Target) (*fakeStore, *fakeScanner, *Runner, store.ScanConfig) {
	t.Helper()
	fs := newFakeStore()
	cfg := store.ScanConfig{ID: 1, Name: "lab", TopPorts: 100, MaxRate: 1000, Workers: 4, Enabled: true}
	for i, tg := range targets {
		tg.ID = int64(i + 1)
		fs.targets[tg.ID] = tg
		cfg.TargetIDs = append(cfg.TargetIDs, tg.ID)
	}
	fs.configs = []store.ScanConfig{cfg}
	sc := &fakeScanner{block: map[netip.Prefix]bool{}, fail: map[netip.Prefix]bool{}}
	r := New(fs, sc, labAllow(), false, quiet)
	return fs, sc, r, cfg
}

func TestExecuteAllChunksOnce(t *testing.T) {
	fs, sc, r, cfg := setup(t,
		model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/21"}, // 8 chunks
		model.Target{Kind: model.TargetIP, Value: "10.20.9.9"},      // 1 chunk, down
	)
	var hooked []int64
	r.OnDone = func(_ context.Context, id int64) error { hooked = append(hooked, id); return nil }
	runID, err := r.RunConfig(context.Background(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := fs.runStatus(runID); got != store.RunDone {
		t.Errorf("run status = %s", got)
	}
	if len(hooked) != 1 || hooked[0] != runID {
		t.Errorf("OnDone calls = %v", hooked)
	}
	if len(fs.chunks) != 9 {
		t.Fatalf("chunks = %d, want 9", len(fs.chunks))
	}
	for _, c := range fs.chunks {
		if c.status != store.ChunkDone || fs.leases[c.ID] != 1 {
			t.Errorf("chunk %s: status=%s leases=%d", c.Prefix, c.status, fs.leases[c.ID])
		}
	}
	up, down := 0, 0
	for _, h := range fs.hosts {
		if h.RunID != runID {
			t.Errorf("host obs run id %d", h.RunID)
		}
		if h.Up {
			up++
		} else {
			down++
		}
	}
	if up != 8 || down != 1 || len(fs.services) != 8 {
		t.Errorf("up=%d down=%d services=%d", up, down, len(fs.services))
	}
	for _, s := range fs.services {
		if s.RunID != runID {
			t.Errorf("service run id %d", s.RunID)
		}
	}
	for _, rate := range sc.rates {
		if rate != 250 {
			t.Errorf("per-worker rate = %d, want 1000/4", rate)
		}
	}
}

func TestInterruptedChunkReturnsToPending(t *testing.T) {
	fs, sc, r, cfg := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	cfg.Workers = 1
	blocked := netip.MustParsePrefix("10.20.1.0/24")
	sc.block[blocked] = true

	runID, err := r.CreateRun(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond) // window end
	defer cancel()
	if err := r.Execute(ctx, runID, cfg); err != nil {
		t.Fatal(err)
	}
	if got := fs.runStatus(runID); got != store.RunPaused {
		t.Fatalf("run status = %s, want paused", got)
	}
	var pending *fakeChunk
	for _, c := range fs.chunks {
		if c.Prefix == blocked {
			pending = c
		} else if c.status != store.ChunkDone {
			t.Errorf("chunk %s status %s", c.Prefix, c.status)
		}
	}
	if pending.status != store.ChunkPending || pending.lastErr == "" {
		t.Errorf("interrupted chunk: %+v", pending)
	}

	// Next window: the chunk is picked up again and the run completes.
	sc.mu.Lock()
	sc.block[blocked] = false
	sc.mu.Unlock()
	if err := r.Execute(context.Background(), runID, cfg); err != nil {
		t.Fatal(err)
	}
	if got := fs.runStatus(runID); got != store.RunDone {
		t.Errorf("run status after resume = %s", got)
	}
	if pending.Attempts != 1 || fs.leases[pending.ID] != 2 {
		t.Errorf("attempts = %d leases = %d, want 1 (interruption refunded) and 2", pending.Attempts, fs.leases[pending.ID])
	}
	if fs.runs[runID].durationMs < 100 {
		t.Errorf("duration_ms = %d, want active time of both sessions", fs.runs[runID].durationMs)
	}
}

func TestFailingChunkRetriesThenFails(t *testing.T) {
	fs, sc, r, cfg := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	bad := netip.MustParsePrefix("10.20.0.0/24")
	sc.fail[bad] = true
	runID, err := r.RunConfig(context.Background(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fs.chunks {
		if c.Prefix == bad {
			if c.status != store.ChunkFailed || c.Attempts != DefaultMaxAttempts || c.lastErr == "" {
				t.Errorf("bad chunk: %+v", c)
			}
		} else if c.status != store.ChunkDone {
			t.Errorf("good chunk %s: %s", c.Prefix, c.status)
		}
	}
	if got := fs.runStatus(runID); got != store.RunDone {
		t.Errorf("run status = %s (partial success counts as done)", got)
	}

	// Every chunk failing fails the run.
	sc.fail[netip.MustParsePrefix("10.20.1.0/24")] = true
	runID, err = r.RunConfig(context.Background(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := fs.runStatus(runID); got != store.RunFailed {
		t.Errorf("run status = %s, want failed", got)
	}
}

func TestRecoverResetsRunning(t *testing.T) {
	fs, _, r, cfg := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	runID, _ := r.CreateRun(context.Background(), cfg)
	_ = fs.StartRun(context.Background(), runID)
	c, _, _ := fs.LeaseChunk(context.Background(), runID) // process "crashes" here
	if err := r.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := fs.chunk(c.ID).status; got != store.ChunkPending {
		t.Errorf("chunk status = %s", got)
	}
	if got := fs.runStatus(runID); got != store.RunPaused {
		t.Errorf("run status = %s", got)
	}
}

func TestRunStatusAndRate(t *testing.T) {
	cases := []struct {
		c    store.ChunkCounts
		want string
	}{
		{store.ChunkCounts{Done: 3}, store.RunDone},
		{store.ChunkCounts{Done: 2, Failed: 1}, store.RunDone},
		{store.ChunkCounts{Failed: 2}, store.RunFailed},
		{store.ChunkCounts{Done: 2, Pending: 1}, store.RunPaused},
		{store.ChunkCounts{}, store.RunDone},
	}
	for _, c := range cases {
		if got := RunStatus(c.c); got != c.want {
			t.Errorf("RunStatus(%+v) = %s, want %s", c.c, got, c.want)
		}
	}
	if PerWorkerRate(1000, 4) != 250 || PerWorkerRate(3, 8) != 1 || PerWorkerRate(0, 4) != 0 || PerWorkerRate(100, 0) != 100 {
		t.Error("PerWorkerRate")
	}
}

// The auto port profile is decided per chunk: a single address keeps -p- and
// the deep version pass when the run also covers a large range.
func TestAutoProfilePerChunk(t *testing.T) {
	_, sc, r, cfg := setup(t,
		model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"},
		model.Target{Kind: model.TargetIP, Value: "10.20.9.9"},
		model.Target{Kind: model.TargetCIDR, Value: "10.20.10.0/28"},
	)
	r.AllPortsMaxAddrs = 16
	if _, err := r.RunConfig(context.Background(), cfg.ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"10.20.9.9/32", "10.20.10.0/28"} {
		o := sc.opts[netip.MustParsePrefix(c)]
		if len(o.Ports) != 65535 || !o.DeepUnknown {
			t.Errorf("%s: ports=%d deep=%v, want all ports + deep pass", c, len(o.Ports), o.DeepUnknown)
		}
	}
	o := sc.opts[netip.MustParsePrefix("10.20.0.0/24")]
	if o.Ports != nil || o.DeepUnknown {
		t.Errorf("/24: ports=%d deep=%v, want top ports without deep pass", len(o.Ports), o.DeepUnknown)
	}
}
