package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunRow is a scan run with chunk progress.
type RunRow struct {
	ID          int64
	ConfigID    *int64
	ConfigName  string
	Kind        string
	Status      string
	StartedAt   *time.Time
	FinishedAt  *time.Time
	DurationMS  *int64
	ChunksTotal int
	ChunksDone  int
	ChunksFail  int
	HostsUp     int
	Services    int
	Stopped     bool // stopped by a user; the scheduler leaves it alone
	Active      bool // executing in this process
}

// Percent is the share of finished chunks.
func (r RunRow) Percent() int {
	if r.ChunksTotal == 0 {
		if r.Status == "done" {
			return 100
		}
		return 0
	}
	return (r.ChunksDone + r.ChunksFail) * 100 / r.ChunksTotal
}

// Duration formats the active scan time.
func (r RunRow) Duration() string {
	if r.DurationMS != nil {
		return (time.Duration(*r.DurationMS) * time.Millisecond).Round(time.Second).String()
	}
	if r.StartedAt != nil && (r.Status == "running") {
		return time.Since(*r.StartedAt).Round(time.Second).String() + " (trwa)"
	}
	return "–"
}

const runCols = `r.id, r.config_id, COALESCE(c.name, ''), r.kind, r.status, r.started_at, r.finished_at, r.duration_ms,
	(SELECT count(*) FROM scan_chunks k WHERE k.run_id = r.id),
	(SELECT count(*) FROM scan_chunks k WHERE k.run_id = r.id AND k.status = 'done'),
	(SELECT count(*) FROM scan_chunks k WHERE k.run_id = r.id AND k.status = 'failed'),
	(SELECT count(*) FROM host_obs h WHERE h.run_id = r.id AND h.up),
	(SELECT count(*) FROM services s WHERE s.run_id = r.id), r.stopped`

// Open reports whether the run can still continue (queued or paused).
func (r RunRow) Open() bool { return r.Status == "queued" || r.Status == "paused" }

func scanRun(row pgx.Row) (RunRow, error) {
	var r RunRow
	err := row.Scan(&r.ID, &r.ConfigID, &r.ConfigName, &r.Kind, &r.Status, &r.StartedAt, &r.FinishedAt, &r.DurationMS,
		&r.ChunksTotal, &r.ChunksDone, &r.ChunksFail, &r.HostsUp, &r.Services, &r.Stopped)
	return r, err
}

// ListRuns returns the newest runs first.
func ListRuns(ctx context.Context, db *pgxpool.Pool, limit int) ([]RunRow, error) {
	rows, err := db.Query(ctx, `SELECT `+runCols+` FROM scan_runs r LEFT JOIN scan_configs c ON c.id = r.config_id
		ORDER BY r.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunRow
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRun returns one run.
func GetRun(ctx context.Context, db *pgxpool.Pool, id int64) (RunRow, error) {
	return scanRun(db.QueryRow(ctx, `SELECT `+runCols+` FROM scan_runs r LEFT JOIN scan_configs c ON c.id = r.config_id
		WHERE r.id = $1`, id))
}

// LatestDoneRun returns the id of the newest finished scan run, or of the
// newest finished import when no scan has finished yet (0 if none). An
// import holds only the hosts in its file, so it is never preferred over a
// full scan for the dashboard and result defaults.
func LatestDoneRun(ctx context.Context, db *pgxpool.Pool) (int64, error) {
	var id int64
	err := db.QueryRow(ctx, `SELECT id FROM scan_runs WHERE status='done'
		ORDER BY (kind = 'scan') DESC, id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// KV is a label with a count.
type KV struct {
	Key   string
	Count int
}

// Finding is a notable detection (admin panel, staging, TLS problem).
type Finding struct {
	ServiceID  int64
	IP         string
	Port       int
	Proto      string
	VHost      string
	Signature  string
	Name       string
	Category   string
	Confidence int
}

// ChangeRow is one change for the dashboard.
type ChangeRow struct {
	RunID int64
	Kind  string
	IP    string
	Port  int
	Proto string
	Field string
	Old   string
	New   string
}

// HostRow is a host lifecycle state.
type HostRow struct {
	IP     string
	State  string
	Misses int
	Flips  []struct {
		Run int64 `json:"run"`
		Up  bool  `json:"up"`
	}
	LastSeen time.Time
}

// Dashboard holds every number shown on "/".
type Dashboard struct {
	Targets       int
	TargetAddrs   int64
	RunID         int64
	LiveHosts     int
	Services      int
	HTTPServices  int
	Detections    int
	ByCategory    []KV
	Notable       []Finding
	TLSProblems   int
	LatestRun     *RunRow
	ActiveRuns    []RunRow
	ChangeRunID   int64
	ChangesByKind []KV
	Changes       []ChangeRow
	StateCounts   []KV
	Unstable      []HostRow
	TopProducts   []KV
}

// LoadDashboard computes the dashboard from the newest finished run.
func LoadDashboard(ctx context.Context, db *pgxpool.Pool) (Dashboard, error) {
	var d Dashboard
	if err := db.QueryRow(ctx, `SELECT count(*),
		LEAST(COALESCE(sum(CASE WHEN kind='cidr' THEN LEAST(2^(CASE WHEN family(value::inet)=4 THEN 32 ELSE 128 END - masklen(value::inet)), 1e15) ELSE 1 END), 0), 1e15)::bigint
		FROM targets`).Scan(&d.Targets, &d.TargetAddrs); err != nil {
		return d, err
	}
	var err error
	if d.RunID, err = LatestDoneRun(ctx, db); err != nil {
		return d, err
	}
	runs, err := ListRuns(ctx, db, 10)
	if err != nil {
		return d, err
	}
	if len(runs) > 0 {
		d.LatestRun = &runs[0]
	}
	for _, r := range runs {
		if r.Status == "running" || r.Status == "queued" || r.Status == "paused" {
			d.ActiveRuns = append(d.ActiveRuns, r)
		}
	}
	if d.RunID != 0 {
		if err := db.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM host_obs WHERE run_id=$1 AND up),
			(SELECT count(*) FROM services WHERE run_id=$1),
			(SELECT count(*) FROM http_obs h JOIN services s ON s.id=h.service_id WHERE s.run_id=$1),
			(SELECT count(*) FROM detections d JOIN services s ON s.id=d.service_id WHERE s.run_id=$1),
			(SELECT count(*) FROM detections d JOIN services s ON s.id=d.service_id WHERE s.run_id=$1
			   AND d.signature_id IN ('tls-expired','tls-self-signed'))`, d.RunID).
			Scan(&d.LiveHosts, &d.Services, &d.HTTPServices, &d.Detections, &d.TLSProblems); err != nil {
			return d, err
		}
		if d.ByCategory, err = kvs(ctx, db, `SELECT d.category, count(*) FROM detections d JOIN services s ON s.id=d.service_id
			WHERE s.run_id=$1 GROUP BY 1 ORDER BY 2 DESC, 1`, d.RunID); err != nil {
			return d, err
		}
		if d.TopProducts, err = kvs(ctx, db, `SELECT CASE WHEN product='' THEN banner ELSE product END, count(*) FROM services
			WHERE run_id=$1 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`, d.RunID); err != nil {
			return d, err
		}
		if d.Notable, err = findings(ctx, db, `WHERE s.run_id=$1 AND d.category IN ('admin-panel','staging')
			ORDER BY d.category, s.ip, s.port LIMIT 50`, d.RunID); err != nil {
			return d, err
		}
	}
	if err := db.QueryRow(ctx, `SELECT COALESCE(max(run_id),0) FROM changes`).Scan(&d.ChangeRunID); err != nil {
		return d, err
	}
	if d.ChangeRunID != 0 {
		if d.ChangesByKind, err = kvs(ctx, db, `SELECT kind, count(*) FROM changes WHERE run_id=$1 GROUP BY 1 ORDER BY 1`, d.ChangeRunID); err != nil {
			return d, err
		}
		rows, err := db.Query(ctx, `SELECT run_id, kind, host(ip), port, proto, field, old, new FROM changes
			WHERE run_id=$1 ORDER BY kind, ip, port LIMIT 25`, d.ChangeRunID)
		if err != nil {
			return d, err
		}
		for rows.Next() {
			var c ChangeRow
			if err := rows.Scan(&c.RunID, &c.Kind, &c.IP, &c.Port, &c.Proto, &c.Field, &c.Old, &c.New); err != nil {
				rows.Close()
				return d, err
			}
			d.Changes = append(d.Changes, c)
		}
		rows.Close()
	}
	if d.StateCounts, err = kvs(ctx, db, `SELECT state, count(*) FROM host_state GROUP BY 1 ORDER BY 1`); err != nil {
		return d, err
	}
	if d.Unstable, err = hostStates(ctx, db, `WHERE state='unstable' ORDER BY ip LIMIT 50`); err != nil {
		return d, err
	}
	return d, nil
}

func kvs(ctx context.Context, db *pgxpool.Pool, q string, args ...any) ([]KV, error) {
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KV
	for rows.Next() {
		var kv KV
		if err := rows.Scan(&kv.Key, &kv.Count); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}

func findings(ctx context.Context, db *pgxpool.Pool, where string, args ...any) ([]Finding, error) {
	rows, err := db.Query(ctx, `SELECT s.id, host(s.ip), s.port, s.proto, s.vhost, d.signature_id, d.name, d.category, d.confidence
		FROM detections d JOIN services s ON s.id = d.service_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ServiceID, &f.IP, &f.Port, &f.Proto, &f.VHost, &f.Signature, &f.Name, &f.Category, &f.Confidence); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func hostStates(ctx context.Context, db *pgxpool.Pool, where string, args ...any) ([]HostRow, error) {
	rows, err := db.Query(ctx, `SELECT host(ip), state, misses, flips, last_seen FROM host_state `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostRow
	for rows.Next() {
		var h HostRow
		var flips []byte
		if err := rows.Scan(&h.IP, &h.State, &h.Misses, &flips, &h.LastSeen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(flips, &h.Flips)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ServiceRow is one service of a run for the results page.
type ServiceRow struct {
	ID         int64
	IP         string
	Port       int
	Proto      string
	VHost      string
	Hostname   string
	Banner     string
	Product    string
	Version    string
	ExtraInfo  string
	Status     *int
	Title      string
	URL        string
	ResponseMS *int // HTTP response time of the probe, nil = not measured
	Detections []DetectionTag
	Annotation string
	Severity   string
	FalsePos   bool
}

// DetectionTag is a short detection label.
type DetectionTag struct {
	Signature  string `json:"signature"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
	Severity   string `json:"severity,omitempty"` // signature severity (evidence), e.g. High for an outdated version
}

// ResultFilter narrows the results list.
type ResultFilter struct {
	RunID    int64
	Category string
	Query    string
}

// ListServices returns the services of a run with HTTP and detection data.
func ListServices(ctx context.Context, db *pgxpool.Pool, f ResultFilter) ([]ServiceRow, error) {
	rows, err := db.Query(ctx, `
		SELECT s.id, host(s.ip), s.port, s.proto, s.vhost, COALESCE(h.hostname, ''), s.banner, s.product, s.version, s.extrainfo,
		       o.status, COALESCE(o.title, ''), COALESCE(o.url, ''), o.response_ms,
		       COALESCE((SELECT json_agg(json_build_object('signature', d.signature_id, 'name', d.name, 'category', d.category,
		                 'confidence', d.confidence, 'severity', COALESCE(d.evidence->>'severity', '')) ORDER BY d.confidence DESC, d.signature_id)
		                 FROM detections d WHERE d.service_id = s.id), '[]'::json),
		       COALESCE(a.comment, ''), COALESCE(a.severity, ''), COALESCE(a.false_positive, false)
		FROM services s
		LEFT JOIN host_obs h ON h.run_id = s.run_id AND h.ip = s.ip
		LEFT JOIN http_obs o ON o.service_id = s.id
		LEFT JOIN annotations a ON a.ip = s.ip AND a.port = s.port AND a.proto = s.proto AND a.vhost = s.vhost
		WHERE s.run_id = $1
		  AND ($2 = '' OR EXISTS (SELECT 1 FROM detections d WHERE d.service_id = s.id AND d.category = $2))
		  AND ($3 = '' OR host(s.ip) LIKE '%' || $3 || '%' OR s.product ILIKE '%' || $3 || '%'
		       OR s.banner ILIKE '%' || $3 || '%' OR COALESCE(o.title, '') ILIKE '%' || $3 || '%'
		       OR EXISTS (SELECT 1 FROM detections d WHERE d.service_id = s.id AND (d.signature_id ILIKE '%' || $3 || '%' OR d.name ILIKE '%' || $3 || '%')))
		ORDER BY s.ip, s.port, s.proto, s.vhost
		LIMIT 5000`, f.RunID, f.Category, f.Query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceRow
	for rows.Next() {
		var s ServiceRow
		var dets []byte
		if err := rows.Scan(&s.ID, &s.IP, &s.Port, &s.Proto, &s.VHost, &s.Hostname, &s.Banner, &s.Product, &s.Version, &s.ExtraInfo,
			&s.Status, &s.Title, &s.URL, &s.ResponseMS, &dets, &s.Annotation, &s.Severity, &s.FalsePos); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dets, &s.Detections)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ServiceDetail is everything known about one service.
type ServiceDetail struct {
	ServiceRow
	RunID int64
	CPE   string
}

// GetService loads one service row.
func GetService(ctx context.Context, db *pgxpool.Pool, id int64) (ServiceDetail, error) {
	var d ServiceDetail
	err := db.QueryRow(ctx, `SELECT s.id, s.run_id, host(s.ip), s.port, s.proto, s.vhost, COALESCE(h.hostname, ''), s.banner,
		s.product, s.version, s.extrainfo, s.cpe
		FROM services s LEFT JOIN host_obs h ON h.run_id = s.run_id AND h.ip = s.ip WHERE s.id = $1`, id).
		Scan(&d.ID, &d.RunID, &d.IP, &d.Port, &d.Proto, &d.VHost, &d.Hostname, &d.Banner, &d.Product, &d.Version, &d.ExtraInfo, &d.CPE)
	return d, err
}
