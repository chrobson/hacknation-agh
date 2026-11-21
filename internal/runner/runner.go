// Package runner executes scan runs: it splits targets into chunks stored in
// scan_chunks, leases them to K worker goroutines (FOR UPDATE SKIP LOCKED in
// the store), runs the two nmap phases per chunk with a per-worker rate R/K,
// stops at the end of the scan window and persists observations.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/scan"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/target"
)

// Store is the persistence the runner needs; *store.ScanStore implements it.
type Store interface {
	ResetRunning(ctx context.Context) (int64, error)
	Configs(ctx context.Context) ([]store.ScanConfig, error)
	Config(ctx context.Context, id int64) (store.ScanConfig, error)
	TargetsByIDs(ctx context.Context, ids []int64) ([]model.Target, error)
	CreateRun(ctx context.Context, configID *int64, chunks []netip.Prefix) (int64, error)
	LastRun(ctx context.Context, configID int64) (*store.RunInfo, error)
	OpenRuns(ctx context.Context) ([]store.RunInfo, error)
	StartRun(ctx context.Context, runID int64) error
	LeaseChunk(ctx context.Context, runID int64) (store.Chunk, bool, error)
	CompleteChunk(ctx context.Context, c store.Chunk, dur time.Duration, hosts []model.HostObs, svcs []model.ServiceObs) error
	ReleaseChunk(ctx context.Context, chunkID int64, reason string) error
	InterruptChunk(ctx context.Context, chunkID int64, reason string) error
	FailChunk(ctx context.Context, chunkID int64, reason string) error
	CountChunks(ctx context.Context, runID int64) (store.ChunkCounts, error)
	FinishRun(ctx context.Context, runID int64, status string, active time.Duration) error
}

var _ Store = (*store.ScanStore)(nil)

// DefaultMaxAttempts is how many times a chunk is tried before it fails.
const DefaultMaxAttempts = 3

// Runner executes scan runs and schedules them (see Tick).
type Runner struct {
	Store       Store
	Scanner     scan.Scanner
	Allow       target.Allowlist
	Privileged  bool     // -sS instead of -sT
	Resolve     Resolver // domain targets; nil = net.DefaultResolver
	Log         *slog.Logger
	Now         func() time.Time
	MaxAttempts int
	ChunkBits4  int
	// OnDone, if set, is called after a run is marked done (all chunks
	// finished), e.g. HTTP fingerprinting then diff.ApplyRun. Its error is
	// logged and returned by Execute.
	OnDone func(ctx context.Context, runID int64) error

	mu     sync.Mutex
	active map[int64]*activeRun // by run id
	wg     sync.WaitGroup
}

type activeRun struct {
	configID int64
	manual   bool // started by RunConfig/StartConfig: ignores the window
	cancel   context.CancelFunc
}

// New returns a Runner with defaults. scanner is typically scan.NewNmap(...).
func New(st Store, scanner scan.Scanner, allow target.Allowlist, privileged bool, log *slog.Logger) *Runner {
	return &Runner{Store: st, Scanner: scanner, Allow: allow, Privileged: privileged, Log: log}
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) maxAttempts() int {
	if r.MaxAttempts > 0 {
		return r.MaxAttempts
	}
	return DefaultMaxAttempts
}

func (r *Runner) resolver() Resolver {
	if r.Resolve != nil {
		return r.Resolve
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
}

// Recover must be called once on startup, before Tick: chunks left running
// by a previous process return to pending and their runs become paused.
func (r *Runner) Recover(ctx context.Context) error {
	n, err := r.Store.ResetRunning(ctx)
	if err != nil {
		return fmt.Errorf("reset running chunks: %w", err)
	}
	if n > 0 {
		r.log().Info("scan chunks reset to pending", "count", n)
	}
	return nil
}

// CreateRun expands the config's targets into chunks and inserts a queued run.
func (r *Runner) CreateRun(ctx context.Context, cfg store.ScanConfig) (int64, error) {
	plan, err := r.plan(ctx, cfg)
	if err != nil {
		return 0, err
	}
	for _, s := range plan.Skipped {
		r.log().Warn("target skipped", "config", cfg.Name, "reason", s)
	}
	if len(plan.Chunks) == 0 {
		return 0, fmt.Errorf("konfiguracja %q nie ma celów do skanowania", cfg.Name)
	}
	id := cfg.ID
	return r.Store.CreateRun(ctx, &id, plan.Chunks)
}

func (r *Runner) plan(ctx context.Context, cfg store.ScanConfig) (Plan, error) {
	targets, err := r.Store.TargetsByIDs(ctx, cfg.TargetIDs)
	if err != nil {
		return Plan{}, err
	}
	return BuildPlan(ctx, targets, r.Allow, r.resolver(), r.ChunkBits4), nil
}

// RunConfig creates a run for the config and executes it now, ignoring the
// window (manual "scan now", `asi scan`). It blocks until the run ends or
// ctx is done; an interrupted run stays paused and is resumed by Tick.
func (r *Runner) RunConfig(ctx context.Context, configID int64) (int64, error) {
	cfg, err := r.Store.Config(ctx, configID)
	if err != nil {
		return 0, err
	}
	if r.configActive(cfg.ID) {
		return 0, fmt.Errorf("skan konfiguracji %q już trwa", cfg.Name)
	}
	runID, err := r.CreateRun(ctx, cfg)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !r.register(runID, cfg.ID, true, cancel) {
		return runID, fmt.Errorf("run %d already active", runID)
	}
	defer r.unregister(runID)
	return runID, r.Execute(ctx, runID, cfg)
}

// StartConfig is the non-blocking variant of RunConfig for the web UI. The
// run is bound to base, which should live as long as the process.
func (r *Runner) StartConfig(base context.Context, configID int64) (int64, error) {
	cfg, err := r.Store.Config(base, configID)
	if err != nil {
		return 0, err
	}
	if r.configActive(cfg.ID) {
		return 0, fmt.Errorf("skan konfiguracji %q już trwa", cfg.Name)
	}
	runID, err := r.CreateRun(base, cfg)
	if err != nil {
		return 0, err
	}
	r.launch(base, runID, cfg, time.Time{}, true)
	return runID, nil
}

// Execute runs the pending chunks of a run with cfg.Workers workers until no
// chunk is left or ctx ends (window end / shutdown). The run is then marked
// done, failed (every chunk failed) or paused (chunks left).
func (r *Runner) Execute(ctx context.Context, runID int64, cfg store.ScanConfig) error {
	started := r.now()
	if err := r.Store.StartRun(ctx, runID); err != nil {
		return err
	}
	plan, err := r.plan(ctx, cfg)
	if err != nil {
		r.log().Warn("cannot load targets for hostnames", "run", runID, "err", err)
	}
	k := max(cfg.Workers, 1)
	opts := scan.Opts{TopPorts: cfg.TopPorts, MaxRate: PerWorkerRate(cfg.MaxRate, k), Privileged: r.Privileged}
	r.log().Info("scan run started", "run", runID, "config", cfg.Name, "workers", k, "rate_per_worker", opts.MaxRate)

	var wg sync.WaitGroup
	errc := make(chan error, k)
	for w := 0; w < k; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.worker(ctx, runID, opts, plan.Hostnames); err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	var werr error
	for e := range errc {
		werr = errors.Join(werr, e)
	}

	// Persist the outcome even if ctx is already done.
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	counts, err := r.Store.CountChunks(dbctx, runID)
	if err != nil {
		return errors.Join(werr, err)
	}
	status := RunStatus(counts)
	active := r.now().Sub(started)
	if err := r.Store.FinishRun(dbctx, runID, status, active); err != nil {
		return errors.Join(werr, err)
	}
	r.log().Info("scan run stopped", "run", runID, "status", status, "active_ms", active.Milliseconds(),
		"done", counts.Done, "failed", counts.Failed, "pending", counts.Pending)
	if status == store.RunDone && r.OnDone != nil {
		// Post-processing is not bound to the window deadline.
		if err := r.OnDone(context.WithoutCancel(ctx), runID); err != nil {
			r.log().Error("post-run hook failed", "run", runID, "err", err)
			werr = errors.Join(werr, fmt.Errorf("post-run hook: %w", err))
		}
	}
	return werr
}

// RunStatus derives the run status from chunk counts after workers stopped.
func RunStatus(c store.ChunkCounts) string {
	switch {
	case c.Pending > 0 || c.Running > 0:
		return store.RunPaused
	case c.Done == 0 && c.Failed > 0:
		return store.RunFailed
	default:
		return store.RunDone
	}
}

// PerWorkerRate splits the run's max rate R across K workers (at least 1
// packet/s each). 0 means unlimited.
func PerWorkerRate(r, k int) int {
	if r <= 0 {
		return 0
	}
	return max(r/max(k, 1), 1)
}

func (r *Runner) worker(ctx context.Context, runID int64, o scan.Opts, hostnames map[netip.Addr]string) error {
	for ctx.Err() == nil {
		c, ok, err := r.Store.LeaseChunk(ctx, runID)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("lease chunk: %w", err)
		}
		if !ok {
			return nil
		}
		if err := r.processChunk(ctx, c, o, hostnames); err != nil {
			return err
		}
	}
	return nil
}

// processChunk scans one chunk. Only store errors are returned; scan errors
// are recorded on the chunk (retry or fail).
func (r *Runner) processChunk(ctx context.Context, c store.Chunk, o scan.Opts, hostnames map[netip.Addr]string) error {
	t0 := r.now()
	hosts, svcs, err := r.scanChunk(ctx, c.Prefix, o)
	dur := r.now().Sub(t0)

	// DB writes must survive the window deadline that may have just fired.
	dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			r.log().Info("chunk interrupted, back to pending", "run", c.RunID, "chunk", c.ID)
			// An interruption is not a failed attempt: refund it so a large
			// chunk cut by several windows is not failed on its next error.
			return r.Store.InterruptChunk(dbctx, c.ID, "przerwano (koniec okna lub zatrzymanie)")
		}
		r.log().Warn("chunk scan failed", "run", c.RunID, "chunk", c.ID, "attempt", c.Attempts, "err", err)
		if c.Attempts >= r.maxAttempts() || errors.Is(err, target.ErrNotAllowed) {
			return r.Store.FailChunk(dbctx, c.ID, err.Error())
		}
		return r.Store.ReleaseChunk(dbctx, c.ID, err.Error())
	}

	obs := make([]model.HostObs, 0, len(hosts)+1)
	for _, h := range hosts {
		obs = append(obs, model.HostObs{RunID: c.RunID, IP: h, Hostname: hostnames[h], Up: true})
	}
	// An explicitly listed single address that did not answer is recorded as
	// down; for CIDR chunks only live hosts are stored (absence = down).
	if c.Prefix.IsSingleIP() && len(hosts) == 0 {
		a := c.Prefix.Addr()
		obs = append(obs, model.HostObs{RunID: c.RunID, IP: a, Hostname: hostnames[a], Up: false})
	}
	for i := range svcs {
		svcs[i].RunID = c.RunID
	}
	return r.Store.CompleteChunk(dbctx, c, dur, obs, svcs)
}

func (r *Runner) scanChunk(ctx context.Context, p netip.Prefix, o scan.Opts) ([]netip.Addr, []model.ServiceObs, error) {
	// Allowlist is enforced again inside the scanner right before exec.
	hosts, err := r.Scanner.Discover(ctx, []netip.Prefix{p}, o)
	if err != nil {
		return nil, nil, fmt.Errorf("discovery: %w", err)
	}
	if len(hosts) == 0 {
		return nil, nil, nil
	}
	svcs, err := r.Scanner.Services(ctx, hosts, o)
	if err != nil {
		return nil, nil, fmt.Errorf("services: %w", err)
	}
	return hosts, svcs, nil
}

// register marks a run active in this process; false if already active.
func (r *Runner) register(runID, configID int64, manual bool, cancel context.CancelFunc) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		r.active = map[int64]*activeRun{}
	}
	if _, ok := r.active[runID]; ok {
		return false
	}
	r.active[runID] = &activeRun{configID: configID, manual: manual, cancel: cancel}
	return true
}

func (r *Runner) unregister(runID int64) {
	r.mu.Lock()
	delete(r.active, runID)
	r.mu.Unlock()
}

func (r *Runner) configActive(configID int64) bool {
	_, ok := r.activeRunFor(configID)
	return ok
}

func (r *Runner) activeRunFor(configID int64) (*activeRun, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.active {
		if a.configID == configID {
			return a, true
		}
	}
	return nil, false
}

func (r *Runner) isActive(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[runID]
	return ok
}

// ActiveRuns returns the ids of runs executing in this process.
func (r *Runner) ActiveRuns() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int64, 0, len(r.active))
	for id := range r.active {
		out = append(out, id)
	}
	return out
}

// Stop cancels a run executing in this process (it becomes paused).
func (r *Runner) Stop(runID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.active[runID]
	if ok {
		a.cancel()
	}
	return ok
}

// launch executes a run in a goroutine, with deadline (zero = none). manual
// runs are not paused by the scheduler outside the window.
func (r *Runner) launch(base context.Context, runID int64, cfg store.ScanConfig, deadline time.Time, manual bool) {
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		ctx, cancel = context.WithCancel(base)
	} else {
		ctx, cancel = context.WithDeadline(base, deadline)
	}
	if !r.register(runID, cfg.ID, manual, cancel) {
		cancel()
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.unregister(runID)
		defer cancel()
		if err := r.Execute(ctx, runID, cfg); err != nil {
			r.log().Error("scan run error", "run", runID, "err", err)
		}
	}()
}

// Wait blocks until all runs launched by Tick/StartConfig have returned.
func (r *Runner) Wait() { r.wg.Wait() }
