// Package store holds plain pgx queries, one file per module.
package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// Scan run statuses (scan_runs.status).
const (
	RunQueued  = "queued"
	RunRunning = "running"
	RunPaused  = "paused"
	RunDone    = "done"
	RunFailed  = "failed"
)

// Chunk statuses (scan_chunks.status).
const (
	ChunkPending = "pending"
	ChunkRunning = "running"
	ChunkDone    = "done"
	ChunkFailed  = "failed"
)

// ScanConfig is one row of scan_configs. Window times are offsets from
// local midnight; WindowEnd may be earlier than WindowStart (crosses midnight).
type ScanConfig struct {
	ID           int64
	Name         string
	TargetIDs    []int64
	TopPorts     int
	MaxRate      int
	Workers      int
	WindowStart  *time.Duration
	WindowEnd    *time.Duration
	EveryMinutes *int
	Enabled      bool
	Ports        string // explicit TCP port list ("22,80,8000-8100"); "" = TopPorts
	ExtraPorts   bool   // second pass over scan.DefaultExtraPorts (only without Ports)
}

// HasWindow reports whether the config restricts scanning to a time window.
func (c ScanConfig) HasWindow() bool { return c.WindowStart != nil && c.WindowEnd != nil }

// Chunk is a leased unit of work.
type Chunk struct {
	ID       int64
	RunID    int64
	Prefix   netip.Prefix
	Attempts int // including the current lease
}

// RunInfo is a summary of a scan_runs row.
type RunInfo struct {
	ID        int64
	ConfigID  *int64
	Status    string
	StartedAt *time.Time
}

// ChunkCounts counts chunks of a run per status.
type ChunkCounts struct {
	Pending, Running, Done, Failed int
}

// ScanStore implements the persistence needed by internal/runner.
type ScanStore struct {
	DB *pgxpool.Pool
}

// NewScanStore returns a ScanStore on the given pool.
func NewScanStore(db *pgxpool.Pool) *ScanStore { return &ScanStore{DB: db} }

// ResetRunning is called on startup: chunks left 'running' by a crashed or
// killed process go back to 'pending' and their runs become 'paused' so the
// scheduler resumes them. Returns the number of chunks reset.
func (s *ScanStore) ResetRunning(ctx context.Context) (int64, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE scan_chunks SET status='pending' WHERE status='running'`)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE scan_runs SET status='paused' WHERE status='running'`); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}

const configCols = `id, name, target_ids, top_ports, max_rate, workers, window_start, window_end, every_minutes, enabled, ports, extra_ports`

func scanConfig(row pgx.Row) (ScanConfig, error) {
	var c ScanConfig
	var ws, we pgtype.Time
	var every pgtype.Int4
	if err := row.Scan(&c.ID, &c.Name, &c.TargetIDs, &c.TopPorts, &c.MaxRate, &c.Workers, &ws, &we, &every, &c.Enabled, &c.Ports, &c.ExtraPorts); err != nil {
		return c, err
	}
	if ws.Valid {
		d := time.Duration(ws.Microseconds) * time.Microsecond
		c.WindowStart = &d
	}
	if we.Valid {
		d := time.Duration(we.Microseconds) * time.Microsecond
		c.WindowEnd = &d
	}
	if every.Valid {
		n := int(every.Int32)
		c.EveryMinutes = &n
	}
	return c, nil
}

// Configs lists all scan configurations.
func (s *ScanStore) Configs(ctx context.Context) ([]ScanConfig, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+configCols+` FROM scan_configs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Config returns one scan configuration.
func (s *ScanStore) Config(ctx context.Context, id int64) (ScanConfig, error) {
	return scanConfig(s.DB.QueryRow(ctx, `SELECT `+configCols+` FROM scan_configs WHERE id=$1`, id))
}

// TargetsByIDs returns the targets with the given ids. An empty list means
// every target (a scan configuration with no explicit targets covers all).
func (s *ScanStore) TargetsByIDs(ctx context.Context, ids []int64) ([]model.Target, error) {
	q, args := `SELECT id, kind, value, tags FROM targets WHERE id = ANY($1) ORDER BY id`, []any{ids}
	if len(ids) == 0 {
		q, args = `SELECT id, kind, value, tags FROM targets ORDER BY id`, nil
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Target
	for rows.Next() {
		var t model.Target
		var kind string
		if err := rows.Scan(&t.ID, &kind, &t.Value, &t.Tags); err != nil {
			return nil, err
		}
		t.Kind = model.TargetKind(kind)
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateRun inserts a queued scan_run with one pending chunk per prefix.
func (s *ScanStore) CreateRun(ctx context.Context, configID *int64, chunks []netip.Prefix) (int64, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var runID int64
	if err := tx.QueryRow(ctx, `INSERT INTO scan_runs (config_id, kind, status) VALUES ($1, 'scan', 'queued') RETURNING id`, configID).Scan(&runID); err != nil {
		return 0, err
	}
	if len(chunks) > 0 {
		rows := make([][]any, len(chunks))
		for i, p := range chunks {
			rows[i] = []any{runID, p.Masked()}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_chunks"}, []string{"run_id", "cidr"}, pgx.CopyFromRows(rows)); err != nil {
			return 0, fmt.Errorf("insert chunks: %w", err)
		}
	}
	return runID, tx.Commit(ctx)
}

func scanRunInfo(row pgx.Row) (RunInfo, error) {
	var r RunInfo
	err := row.Scan(&r.ID, &r.ConfigID, &r.Status, &r.StartedAt)
	return r, err
}

// LastRun returns the most recent run of a config, or nil if there is none.
func (s *ScanStore) LastRun(ctx context.Context, configID int64) (*RunInfo, error) {
	r, err := scanRunInfo(s.DB.QueryRow(ctx,
		`SELECT id, config_id, status, started_at FROM scan_runs WHERE config_id=$1 AND kind='scan' ORDER BY id DESC LIMIT 1`, configID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// OpenRuns lists scan runs that are not finished (queued, running, paused).
func (s *ScanStore) OpenRuns(ctx context.Context) ([]RunInfo, error) {
	rows, err := s.DB.Query(ctx,
		`SELECT id, config_id, status, started_at FROM scan_runs
		 WHERE kind='scan' AND status IN ('queued','running','paused') AND NOT stopped ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunInfo
	for rows.Next() {
		r, err := scanRunInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StartRun marks a run running; started_at keeps the first start.
func (s *ScanStore) StartRun(ctx context.Context, runID int64) error {
	_, err := s.DB.Exec(ctx,
		`UPDATE scan_runs SET status='running', started_at=coalesce(started_at, now()), finished_at=NULL WHERE id=$1`, runID)
	return err
}

// LeaseChunk takes the next pending chunk of a run. Concurrent workers (also
// in other processes) never get the same chunk thanks to SKIP LOCKED.
func (s *ScanStore) LeaseChunk(ctx context.Context, runID int64) (Chunk, bool, error) {
	c := Chunk{RunID: runID}
	err := s.DB.QueryRow(ctx, `
		UPDATE scan_chunks SET status='running', attempts=attempts+1, started_at=now()
		WHERE id = (
			SELECT id FROM scan_chunks
			WHERE run_id=$1 AND status='pending'
			ORDER BY id
			FOR UPDATE SKIP LOCKED
			LIMIT 1)
		RETURNING id, cidr, attempts`, runID).Scan(&c.ID, &c.Prefix, &c.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	return c, true, nil
}

// CompleteChunk persists the observations of a chunk and marks it done, in
// one transaction. hostsUp is recorded on the chunk.
func (s *ScanStore) CompleteChunk(ctx context.Context, c Chunk, dur time.Duration, hosts []model.HostObs, svcs []model.ServiceObs) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := InsertObservations(ctx, tx, c.RunID, hosts, svcs); err != nil {
		return err
	}
	up := 0
	for _, h := range hosts {
		if h.Up {
			up++
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE scan_chunks SET status='done', duration_ms=$2, hosts_up=$3, last_error='' WHERE id=$1`,
		c.ID, dur.Milliseconds(), up); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertObservations writes host_obs and services rows for a run. It is
// idempotent per natural key so overlapping chunks cannot fail a run.
func InsertObservations(ctx context.Context, tx pgx.Tx, runID int64, hosts []model.HostObs, svcs []model.ServiceObs) error {
	b := &pgx.Batch{}
	for _, h := range hosts {
		b.Queue(`INSERT INTO host_obs (run_id, ip, hostname, up) VALUES ($1, $2, $3, $4)
			ON CONFLICT (run_id, ip) DO UPDATE SET up = host_obs.up OR EXCLUDED.up,
			hostname = CASE WHEN host_obs.hostname = '' THEN EXCLUDED.hostname ELSE host_obs.hostname END`,
			runID, h.IP, h.Hostname, h.Up)
	}
	for _, sv := range svcs {
		b.Queue(`INSERT INTO services (run_id, ip, port, proto, vhost, product, version, extrainfo, cpe, banner)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (run_id, ip, port, proto, vhost) DO UPDATE SET product=EXCLUDED.product,
			version=EXCLUDED.version, extrainfo=EXCLUDED.extrainfo, cpe=EXCLUDED.cpe, banner=EXCLUDED.banner`,
			runID, sv.Key.IP, int(sv.Key.Port), sv.Key.Proto, sv.Key.VHost, sv.Product, sv.Version, sv.ExtraInfo, sv.CPE, sv.Banner)
	}
	if b.Len() == 0 {
		return nil
	}
	return tx.SendBatch(ctx, b).Close()
}

// ReleaseChunk returns a chunk to 'pending' (interrupted or retryable error).
func (s *ScanStore) ReleaseChunk(ctx context.Context, chunkID int64, reason string) error {
	_, err := s.DB.Exec(ctx, `UPDATE scan_chunks SET status='pending', last_error=$2 WHERE id=$1`, chunkID, reason)
	return err
}

// InterruptChunk returns a chunk to 'pending' after an interruption (window
// end, stop, shutdown) and refunds the attempt taken by its lease.
func (s *ScanStore) InterruptChunk(ctx context.Context, chunkID int64, reason string) error {
	_, err := s.DB.Exec(ctx, `UPDATE scan_chunks SET status='pending', last_error=$2,
		attempts=greatest(attempts-1, 0) WHERE id=$1`, chunkID, reason)
	return err
}

// FailChunk marks a chunk permanently failed.
func (s *ScanStore) FailChunk(ctx context.Context, chunkID int64, reason string) error {
	_, err := s.DB.Exec(ctx, `UPDATE scan_chunks SET status='failed', last_error=$2 WHERE id=$1`, chunkID, reason)
	return err
}

// CountChunks counts the chunks of a run per status.
func (s *ScanStore) CountChunks(ctx context.Context, runID int64) (ChunkCounts, error) {
	var c ChunkCounts
	err := s.DB.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status='pending'),
		count(*) FILTER (WHERE status='running'),
		count(*) FILTER (WHERE status='done'),
		count(*) FILTER (WHERE status='failed')
		FROM scan_chunks WHERE run_id=$1`, runID).Scan(&c.Pending, &c.Running, &c.Done, &c.Failed)
	return c, err
}

// FinishRun sets the final (or paused) status of a run and adds the active
// scanning time of this session to duration_ms, so a run paused by its
// window reports only the time actually spent scanning.
func (s *ScanStore) FinishRun(ctx context.Context, runID int64, status string, active time.Duration) error {
	_, err := s.DB.Exec(ctx, `UPDATE scan_runs SET status=$2,
		duration_ms = coalesce(duration_ms, 0) + $3,
		finished_at = CASE WHEN $2 IN ('done','failed') THEN now() ELSE NULL END
		WHERE id=$1`, runID, status, active.Milliseconds())
	return err
}
