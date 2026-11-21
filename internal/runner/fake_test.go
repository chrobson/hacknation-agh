package runner

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/scan"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// fakeStore is an in-memory Store. LeaseChunk emulates
// FOR UPDATE SKIP LOCKED: a chunk is handed to exactly one caller.
type fakeStore struct {
	mu       sync.Mutex
	configs  []store.ScanConfig
	targets  map[int64]model.Target
	runs     map[int64]*fakeRun
	chunks   []*fakeChunk
	hosts    []model.HostObs
	services []model.ServiceObs
	leases   map[int64]int // chunk id -> number of leases
	nextID   int64
}

type fakeRun struct {
	store.RunInfo
	durationMs int64
}

type fakeChunk struct {
	store.Chunk
	status   string
	durMs    int64
	hostsUp  int
	lastErr  string
	leasedBy int
}

func newFakeStore() *fakeStore {
	return &fakeStore{targets: map[int64]model.Target{}, runs: map[int64]*fakeRun{}, leases: map[int64]int{}}
}

func (f *fakeStore) id() int64 { f.nextID++; return f.nextID }

func (f *fakeStore) ResetRunning(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, c := range f.chunks {
		if c.status == store.ChunkRunning {
			c.status = store.ChunkPending
			n++
		}
	}
	for _, r := range f.runs {
		if r.Status == store.RunRunning {
			r.Status = store.RunPaused
		}
	}
	return n, nil
}

func (f *fakeStore) Configs(context.Context) ([]store.ScanConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.ScanConfig(nil), f.configs...), nil
}

func (f *fakeStore) Config(_ context.Context, id int64) (store.ScanConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.configs {
		if c.ID == id {
			return c, nil
		}
	}
	return store.ScanConfig{}, errors.New("no config")
}

func (f *fakeStore) TargetsByIDs(_ context.Context, ids []int64) ([]model.Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Target
	for _, id := range ids {
		if t, ok := f.targets[id]; ok {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeStore) CreateRun(_ context.Context, configID *int64, chunks []netip.Prefix) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.id()
	f.runs[id] = &fakeRun{RunInfo: store.RunInfo{ID: id, ConfigID: configID, Status: store.RunQueued}}
	for _, p := range chunks {
		f.chunks = append(f.chunks, &fakeChunk{Chunk: store.Chunk{ID: f.id(), RunID: id, Prefix: p}, status: store.ChunkPending})
	}
	return id, nil
}

func (f *fakeStore) LastRun(_ context.Context, configID int64) (*store.RunInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *store.RunInfo
	for _, r := range f.runs {
		if r.ConfigID != nil && *r.ConfigID == configID && (best == nil || r.ID > best.ID) {
			ri := r.RunInfo
			best = &ri
		}
	}
	return best, nil
}

func (f *fakeStore) OpenRuns(context.Context) ([]store.RunInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.RunInfo
	for _, r := range f.runs {
		switch r.Status {
		case store.RunQueued, store.RunRunning, store.RunPaused:
			out = append(out, r.RunInfo)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) StartRun(_ context.Context, runID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.runs[runID]
	r.Status = store.RunRunning
	if r.StartedAt == nil {
		t := time.Now()
		r.StartedAt = &t
	}
	return nil
}

func (f *fakeStore) LeaseChunk(ctx context.Context, runID int64) (store.Chunk, bool, error) {
	if err := ctx.Err(); err != nil {
		return store.Chunk{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.chunks {
		if c.RunID == runID && c.status == store.ChunkPending {
			c.status = store.ChunkRunning
			c.Attempts++
			f.leases[c.ID]++
			return c.Chunk, true, nil
		}
	}
	return store.Chunk{}, false, nil
}

func (f *fakeStore) chunk(id int64) *fakeChunk {
	for _, c := range f.chunks {
		if c.ID == id {
			return c
		}
	}
	panic("no chunk")
}

func (f *fakeStore) CompleteChunk(_ context.Context, c store.Chunk, dur time.Duration, hosts []model.HostObs, svcs []model.ServiceObs) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fc := f.chunk(c.ID)
	if fc.status != store.ChunkRunning {
		return errors.New("complete of a chunk not running")
	}
	fc.status = store.ChunkDone
	fc.durMs = dur.Milliseconds()
	for _, h := range hosts {
		if h.Up {
			fc.hostsUp++
		}
	}
	f.hosts = append(f.hosts, hosts...)
	f.services = append(f.services, svcs...)
	return nil
}

func (f *fakeStore) ReleaseChunk(_ context.Context, id int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.chunk(id)
	c.status, c.lastErr = store.ChunkPending, reason
	return nil
}

func (f *fakeStore) InterruptChunk(_ context.Context, id int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.chunk(id)
	c.status, c.lastErr = store.ChunkPending, reason
	c.Attempts = max(c.Attempts-1, 0)
	return nil
}

func (f *fakeStore) FailChunk(_ context.Context, id int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.chunk(id)
	c.status, c.lastErr = store.ChunkFailed, reason
	return nil
}

func (f *fakeStore) CountChunks(_ context.Context, runID int64) (store.ChunkCounts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var cc store.ChunkCounts
	for _, c := range f.chunks {
		if c.RunID != runID {
			continue
		}
		switch c.status {
		case store.ChunkPending:
			cc.Pending++
		case store.ChunkRunning:
			cc.Running++
		case store.ChunkDone:
			cc.Done++
		case store.ChunkFailed:
			cc.Failed++
		}
	}
	return cc, nil
}

func (f *fakeStore) FinishRun(_ context.Context, runID int64, status string, active time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.runs[runID]
	r.Status = status
	r.durationMs += active.Milliseconds()
	return nil
}

func (f *fakeStore) runStatus(id int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[id].Status
}

// fakeScanner reports host .10 of every chunk as live with one service.
// block: prefixes for which Discover waits for ctx to end.
// fail: prefixes for which Discover returns an error.
type fakeScanner struct {
	mu      sync.Mutex
	block   map[netip.Prefix]bool
	fail    map[netip.Prefix]bool
	rates   []int
	started chan netip.Prefix
}

func (s *fakeScanner) Discover(ctx context.Context, ps []netip.Prefix, o scan.Opts) ([]netip.Addr, error) {
	s.mu.Lock()
	s.rates = append(s.rates, o.MaxRate)
	block, fail := s.block[ps[0]], s.fail[ps[0]]
	s.mu.Unlock()
	if s.started != nil {
		s.started <- ps[0]
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fail {
		return nil, errors.New("nmap exit 1: boom")
	}
	p := ps[0]
	if p.IsSingleIP() {
		return nil, nil // single addresses are down in this fake
	}
	b := p.Addr().As4()
	b[3] = 10
	return []netip.Addr{netip.AddrFrom4(b)}, nil
}

func (s *fakeScanner) Services(_ context.Context, hosts []netip.Addr, _ scan.Opts) ([]model.ServiceObs, error) {
	var out []model.ServiceObs
	for _, h := range hosts {
		out = append(out, model.ServiceObs{Key: model.AssetKey{IP: h, Port: 80, Proto: "tcp"}, Product: "nginx", Banner: "http"})
	}
	return out, nil
}
