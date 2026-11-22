package runner

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

func ptr[T any](v T) *T { return &v }

func TestDue(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	every := store.ScanConfig{EveryMinutes: ptr(60)}
	if Due(now, store.ScanConfig{}, nil) {
		t.Error("manual config must not be due")
	}
	if !Due(now, every, nil) {
		t.Error("never ran: due")
	}
	if Due(now, every, &store.RunInfo{StartedAt: ptr(now.Add(-59 * time.Minute))}) {
		t.Error("59 min ago: not due")
	}
	if !Due(now, every, &store.RunInfo{StartedAt: ptr(now.Add(-60 * time.Minute))}) {
		t.Error("60 min ago: due")
	}
	if !Due(now, every, &store.RunInfo{}) {
		t.Error("queued run never started: due")
	}
}

func TestTickStartsPausesResumes(t *testing.T) {
	fs, sc, r, _ := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/23"})
	fs.configs[0].Workers = 1
	fs.configs[0].EveryMinutes = ptr(60)
	fs.configs[0].WindowStart = ptr(22 * time.Hour)
	fs.configs[0].WindowEnd = ptr(6 * time.Hour)
	blocked := netip.MustParsePrefix("10.20.0.0/24")
	sc.block[blocked] = true
	sc.started = make(chan netip.Prefix, 16)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loc := time.Local
	// The window end becomes a real context deadline for the run, so the
	// simulated day has to lie in the future: a fixed calendar date makes the
	// run expire at once and the test hang as soon as that date has passed.
	day := time.Now().AddDate(0, 0, 1)
	outside := time.Date(day.Year(), day.Month(), day.Day(), 12, 0, 0, 0, loc)
	inside := time.Date(day.Year(), day.Month(), day.Day(), 23, 0, 0, 0, loc)

	// Outside the window nothing starts.
	if err := r.Tick(ctx, outside); err != nil {
		t.Fatal(err)
	}
	if len(fs.runs) != 0 {
		t.Fatalf("runs outside window: %d", len(fs.runs))
	}

	// Inside: a run starts and blocks on the first chunk.
	if err := r.Tick(ctx, inside); err != nil {
		t.Fatal(err)
	}
	if len(fs.runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(fs.runs))
	}
	<-sc.started
	// A second tick while it runs does not start another one.
	if err := r.Tick(ctx, inside.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(fs.runs) != 1 || len(r.ActiveRuns()) != 1 {
		t.Fatalf("runs = %d active = %d", len(fs.runs), len(r.ActiveRuns()))
	}

	// Leaving the window pauses it; the chunk goes back to pending.
	if err := r.Tick(ctx, inside.Add(8*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	var runID int64
	for id := range fs.runs {
		runID = id
	}
	if got := fs.runStatus(runID); got != store.RunPaused {
		t.Fatalf("status after window = %s", got)
	}

	// Next window resumes the same run (no new run) and finishes it.
	sc.mu.Lock()
	sc.block[blocked] = false
	sc.mu.Unlock()
	if err := r.Tick(ctx, inside.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if len(fs.runs) != 1 {
		t.Fatalf("runs = %d, want the paused one resumed", len(fs.runs))
	}
	if got := fs.runStatus(runID); got != store.RunDone {
		t.Fatalf("status after resume = %s", got)
	}

}

func TestTickWindowDeadline(t *testing.T) {
	fs, sc, r, _ := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	fs.configs[0].EveryMinutes = ptr(5)
	sc.block[netip.MustParsePrefix("10.20.0.0/24")] = true
	// Window ends 150ms from now: the run must stop by its own deadline.
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	start := now.Add(-time.Minute).Sub(midnight)
	end := now.Add(150 * time.Millisecond).Sub(midnight)
	if end >= 24*time.Hour || start < 0 {
		t.Skip("too close to midnight")
	}
	fs.configs[0].WindowStart, fs.configs[0].WindowEnd = &start, &end
	if err := r.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop at window end")
	}
	for id := range fs.runs {
		if got := fs.runStatus(id); got != store.RunPaused {
			t.Errorf("status = %s, want paused", got)
		}
	}
}

func TestTickDisabledAndManual(t *testing.T) {
	fs, _, r, _ := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	fs.configs[0].Enabled = false
	fs.configs[0].EveryMinutes = ptr(1)
	_ = r.Tick(context.Background(), time.Now())
	fs.configs[0].Enabled = true
	fs.configs[0].EveryMinutes = nil
	_ = r.Tick(context.Background(), time.Now())
	r.Wait()
	if len(fs.runs) != 0 {
		t.Errorf("runs = %d, want 0 (disabled / manual)", len(fs.runs))
	}
}

func TestTickKeepsManualRunOutsideWindow(t *testing.T) {
	fs, sc, r, cfg := setup(t, model.Target{Kind: model.TargetCIDR, Value: "10.20.0.0/24"})
	fs.configs[0].WindowStart = ptr(22 * time.Hour)
	fs.configs[0].WindowEnd = ptr(6 * time.Hour)
	blocked := netip.MustParsePrefix("10.20.0.0/24")
	sc.block[blocked] = true
	sc.started = make(chan netip.Prefix, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runID, err := r.StartConfig(ctx, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	<-sc.started
	if _, err := r.StartConfig(ctx, cfg.ID); err == nil {
		t.Error("second manual start of an active config must fail")
	}
	noon := time.Date(2026, 11, 21, 12, 0, 0, 0, time.Local)
	if err := r.Tick(ctx, noon); err != nil {
		t.Fatal(err)
	}
	if got := r.ActiveRuns(); len(got) != 1 || got[0] != runID {
		t.Fatalf("manual run cancelled by the scheduler outside its window: active=%v", got)
	}
	r.Stop(runID)
	r.Wait()
	if got := fs.runStatus(runID); got != store.RunPaused {
		t.Errorf("status after stop = %s, want paused", got)
	}
}
