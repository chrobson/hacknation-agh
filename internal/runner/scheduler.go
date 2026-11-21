package runner

import (
	"context"
	"errors"
	"time"

	"github.com/chrobson/hacknation-agh/internal/store"
)

// Tick is one scheduler step at time now. For every enabled config it:
//   - pauses (cancels) a run executing in this process when now is outside
//     the config's window;
//   - resumes a queued or paused run of the config when inside the window;
//   - starts a new run when every_minutes has elapsed since the last run
//     started and now is inside the window.
//
// Runs are executed in goroutines bound to ctx, which must live as long as
// the process (e.g. the serve context); each run's context has a deadline at
// the end of the current window, so it stops by itself at window end and the
// interrupted chunk returns to pending.
func (r *Runner) Tick(ctx context.Context, now time.Time) error {
	cfgs, err := r.Store.Configs(ctx)
	if err != nil {
		return err
	}
	open, err := r.Store.OpenRuns(ctx)
	if err != nil {
		return err
	}
	openByCfg := map[int64]store.RunInfo{}
	elsewhere := map[int64]bool{}
	for _, o := range open {
		if o.ConfigID == nil {
			continue
		}
		// 'running' rows not executing here belong to another live process
		// (e.g. `asi scan`); rows left by a dead process were reset to
		// paused by Recover. Leave such configs alone.
		if o.Status == store.RunRunning {
			if !r.isActive(o.ID) {
				elsewhere[*o.ConfigID] = true
			}
			continue
		}
		if _, ok := openByCfg[*o.ConfigID]; !ok { // oldest open run first
			openByCfg[*o.ConfigID] = o
		}
	}
	var errs error
	for _, cfg := range cfgs {
		if elsewhere[cfg.ID] {
			continue
		}
		if err := r.tickConfig(ctx, now, cfg, openByCfg); err != nil {
			r.log().Error("scheduler", "config", cfg.Name, "err", err)
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (r *Runner) tickConfig(ctx context.Context, now time.Time, cfg store.ScanConfig, open map[int64]store.RunInfo) error {
	inWin, deadline := true, time.Time{}
	if cfg.HasWindow() {
		from, to := NextWindow(now, *cfg.WindowStart, *cfg.WindowEnd)
		inWin = !now.Before(from) && now.Before(to)
		deadline = to
	}
	if a, ok := r.activeRunFor(cfg.ID); ok {
		// Manual runs ("scan now") ignore the window and stay running.
		if !a.manual && (!inWin || !cfg.Enabled) {
			a.cancel() // the run persists itself as paused
		}
		return nil
	}
	if !cfg.Enabled || !inWin {
		return nil
	}
	if o, ok := open[cfg.ID]; ok {
		r.log().Info("resuming scan run", "run", o.ID, "config", cfg.Name, "until", deadline)
		r.launch(ctx, o.ID, cfg, deadline, false)
		return nil
	}
	if !Due(now, cfg, nil) {
		return nil
	}
	last, err := r.Store.LastRun(ctx, cfg.ID)
	if err != nil {
		return err
	}
	if !Due(now, cfg, last) {
		return nil
	}
	runID, err := r.CreateRun(ctx, cfg)
	if err != nil {
		return err
	}
	r.log().Info("scheduled scan run", "run", runID, "config", cfg.Name, "until", deadline)
	r.launch(ctx, runID, cfg, deadline, false)
	return nil
}

// Due reports whether a periodic config should start a new run at now given
// its last run (nil = never ran). Configs without every_minutes are manual.
func Due(now time.Time, cfg store.ScanConfig, last *store.RunInfo) bool {
	if cfg.EveryMinutes == nil || *cfg.EveryMinutes <= 0 {
		return false
	}
	if last == nil || last.StartedAt == nil {
		return true
	}
	return !now.Before(last.StartedAt.Add(time.Duration(*cfg.EveryMinutes) * time.Minute))
}

// Loop calls Recover once and then Tick every interval until ctx is done,
// then waits for running scans to stop (they are paused, not lost).
func (r *Runner) Loop(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = time.Minute
	}
	if err := r.Recover(ctx); err != nil {
		return err
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := r.Tick(ctx, r.now()); err != nil && ctx.Err() == nil {
			r.log().Error("scheduler tick", "err", err)
		}
		select {
		case <-ctx.Done():
			r.Wait()
			return nil
		case <-t.C:
		}
	}
}
