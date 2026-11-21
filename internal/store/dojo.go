// Package store holds plain pgx queries. This file is owned by W1-6
// (DefectDojo, export and import); identifiers are prefixed to avoid clashes
// with other modules' files in the same package.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/model"
)

// DojoDB is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type DojoDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrNoRun is returned when there is no finished run to export.
var ErrNoRun = errors.New("no finished scan run")

// ExportRun describes the run an export is built from.
type ExportRun struct {
	ID         int64
	Kind       string
	Status     string
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// Date is the day the findings are dated with (finish, start, or now).
func (r ExportRun) Date() time.Time {
	switch {
	case r.FinishedAt != nil:
		return r.FinishedAt.UTC()
	case r.StartedAt != nil:
		return r.StartedAt.UTC()
	}
	return time.Now().UTC()
}

const exportRunCols = `id, kind, status, started_at, finished_at`

func scanExportRun(row pgx.Row) (ExportRun, error) {
	var r ExportRun
	err := row.Scan(&r.ID, &r.Kind, &r.Status, &r.StartedAt, &r.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNoRun
	}
	return r, err
}

// ExportLatestRun returns the most recent finished scan run, or the most
// recent import when no scan has finished.
func ExportLatestRun(ctx context.Context, db DojoDB) (ExportRun, error) {
	return scanExportRun(db.QueryRow(ctx, `SELECT `+exportRunCols+` FROM scan_runs
		WHERE status = 'done'
		ORDER BY (kind = 'scan') DESC, COALESCE(finished_at, started_at) DESC NULLS LAST, id DESC LIMIT 1`))
}

// ExportRunByID returns one finished run.
func ExportRunByID(ctx context.Context, db DojoDB, id int64) (ExportRun, error) {
	return scanExportRun(db.QueryRow(ctx, `SELECT `+exportRunCols+` FROM scan_runs
		WHERE id = $1 AND status = 'done'`, id))
}

// ExportServices loads all services of a run with host name, HTTP summary
// and detections, ordered by IP, port, protocol and virtual host.
func ExportServices(ctx context.Context, db DojoDB, runID int64) ([]dojo.Service, error) {
	rows, err := db.Query(ctx, `
		SELECT s.id, host(s.ip), s.port, s.proto, s.vhost, s.product, s.version,
		       s.extrainfo, s.cpe, s.banner, COALESCE(h.hostname, ''),
		       ho.url, ho.status, COALESCE(ho.title, '')
		FROM services s
		LEFT JOIN host_obs h ON h.run_id = s.run_id AND h.ip = s.ip
		LEFT JOIN http_obs ho ON ho.service_id = s.id
		WHERE s.run_id = $1
		ORDER BY s.ip, s.port, s.proto, s.vhost`, runID)
	if err != nil {
		return nil, err
	}
	var out []dojo.Service
	index := map[int64]int{}
	for rows.Next() {
		var (
			s      dojo.Service
			ip     string
			port   int32
			url    *string
			status *int32
			title  string
		)
		if err := rows.Scan(&s.ID, &ip, &port, &s.Key.Proto, &s.Key.VHost, &s.Product, &s.Version,
			&s.ExtraInfo, &s.CPE, &s.Banner, &s.Hostname, &url, &status, &title); err != nil {
			rows.Close()
			return nil, err
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("service %d: bad ip %q: %w", s.ID, ip, err)
		}
		s.RunID = runID
		s.Key.IP = a
		s.Key.Port = uint16(port)
		if url != nil {
			s.HTTP = &dojo.HTTPSummary{URL: *url, Title: title}
			if status != nil {
				s.HTTP.Status = int(*status)
			}
		}
		index[s.ID] = len(out)
		out = append(out, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	drows, err := db.Query(ctx, `
		SELECT d.service_id, d.signature_id, d.name, d.category, d.confidence, d.evidence
		FROM detections d JOIN services s ON s.id = d.service_id
		WHERE s.run_id = $1
		ORDER BY d.service_id, d.signature_id`, runID)
	if err != nil {
		return nil, err
	}
	defer drows.Close()
	for drows.Next() {
		var (
			d   model.Detection
			ev  []byte
			cfd int32
		)
		if err := drows.Scan(&d.ServiceID, &d.SignatureID, &d.Name, &d.Category, &cfd, &ev); err != nil {
			return nil, err
		}
		d.Confidence = int(cfd)
		d.Evidence = evidenceMap(ev)
		if i, ok := index[d.ServiceID]; ok {
			out[i].Detections = append(out[i].Detections, d)
		}
	}
	return out, drows.Err()
}

// evidenceMap flattens a jsonb evidence object into strings.
func evidenceMap(b []byte) map[string]string {
	if len(b) == 0 {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
			continue
		}
		j, _ := json.Marshal(v)
		out[k] = string(j)
	}
	return out
}

// ExportAnnotations loads all analyst annotations.
func ExportAnnotations(ctx context.Context, db DojoDB) ([]dojo.Annotation, error) {
	rows, err := db.Query(ctx, `SELECT host(ip), port, proto, vhost, comment, tags,
		COALESCE(severity, ''), false_positive FROM annotations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dojo.Annotation
	for rows.Next() {
		var (
			a    dojo.Annotation
			ip   string
			port int32
		)
		if err := rows.Scan(&ip, &port, &a.Key.Proto, &a.Key.VHost, &a.Comment, &a.Tags,
			&a.Severity, &a.FalsePositive); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, err
		}
		a.Key.IP = addr
		a.Key.Port = uint16(port)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ImportBeginRun creates a running scan_run of kind 'import'.
func ImportBeginRun(ctx context.Context, tx pgx.Tx) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO scan_runs (kind, status, started_at)
		VALUES ('import', 'running', now()) RETURNING id`).Scan(&id)
	return id, err
}

// ImportFinishRun marks an import run done.
func ImportFinishRun(ctx context.Context, tx pgx.Tx, runID int64) error {
	_, err := tx.Exec(ctx, `UPDATE scan_runs SET status = 'done', finished_at = now(),
		duration_ms = (EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::bigint
		WHERE id = $1`, runID)
	return err
}

// ImportHost records a host observation; repeated hosts keep the first
// non-empty hostname.
func ImportHost(ctx context.Context, tx pgx.Tx, runID int64, h model.HostObs) error {
	_, err := tx.Exec(ctx, `INSERT INTO host_obs (run_id, ip, hostname, up)
		VALUES ($1, $2::inet, $3, $4)
		ON CONFLICT (run_id, ip) DO UPDATE SET
			hostname = CASE WHEN host_obs.hostname = '' THEN EXCLUDED.hostname ELSE host_obs.hostname END,
			up = host_obs.up OR EXCLUDED.up`,
		runID, h.IP.String(), h.Hostname, h.Up)
	return err
}

// ImportService upserts a service of an import run and returns its id.
// Non-empty fields of a later record fill empty ones of an earlier one.
func ImportService(ctx context.Context, tx pgx.Tx, runID int64, s model.ServiceObs) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO services
		(run_id, ip, port, proto, vhost, product, version, extrainfo, cpe, banner)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (run_id, ip, port, proto, vhost) DO UPDATE SET
			product   = COALESCE(NULLIF(services.product, ''), EXCLUDED.product),
			version   = COALESCE(NULLIF(services.version, ''), EXCLUDED.version),
			extrainfo = COALESCE(NULLIF(services.extrainfo, ''), EXCLUDED.extrainfo),
			cpe       = COALESCE(NULLIF(services.cpe, ''), EXCLUDED.cpe),
			banner    = COALESCE(NULLIF(services.banner, ''), EXCLUDED.banner)
		RETURNING id`,
		runID, s.Key.IP.String(), int32(s.Key.Port), s.Key.Proto, s.Key.VHost,
		s.Product, s.Version, s.ExtraInfo, s.CPE, s.Banner).Scan(&id)
	return id, err
}

// ImportDetection records a detection; duplicates are ignored.
func ImportDetection(ctx context.Context, tx pgx.Tx, d model.Detection) error {
	ev, err := json.Marshal(d.Evidence)
	if err != nil {
		return err
	}
	if d.Evidence == nil {
		ev = []byte("{}")
	}
	_, err = tx.Exec(ctx, `INSERT INTO detections
		(service_id, signature_id, name, category, confidence, evidence)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (service_id, signature_id) DO NOTHING`,
		d.ServiceID, d.SignatureID, d.Name, d.Category, int32(d.Confidence), ev)
	return err
}

// DojoPush is one recorded DefectDojo push attempt.
type DojoPush struct {
	ID         int64
	RunID      *int64
	PushedAt   time.Time
	Endpoint   string
	Findings   int
	TestID     *int64
	OK         bool
	Error      string
	Statistics json.RawMessage
}

// DojoRecordPush stores a push attempt.
func DojoRecordPush(ctx context.Context, db DojoDB, p DojoPush) error {
	stats := p.Statistics
	if len(stats) == 0 {
		stats = json.RawMessage("{}")
	}
	_, err := db.Exec(ctx, `INSERT INTO dojo_pushes
		(run_id, endpoint, findings, test_id, ok, error, statistics)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		p.RunID, p.Endpoint, int32(p.Findings), p.TestID, p.OK, p.Error, []byte(stats))
	return err
}

// DojoRecentPushes returns the latest push attempts, newest first.
func DojoRecentPushes(ctx context.Context, db DojoDB, limit int) ([]DojoPush, error) {
	rows, err := db.Query(ctx, `SELECT id, run_id, pushed_at, endpoint, findings, test_id, ok, error, statistics
		FROM dojo_pushes ORDER BY pushed_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DojoPush
	for rows.Next() {
		var (
			p     DojoPush
			n     int32
			stats []byte
		)
		if err := rows.Scan(&p.ID, &p.RunID, &p.PushedAt, &p.Endpoint, &n, &p.TestID, &p.OK, &p.Error, &stats); err != nil {
			return nil, err
		}
		p.Findings = int(n)
		p.Statistics = stats
		out = append(out, p)
	}
	return out, rows.Err()
}

// DojoAudit appends an audit_log entry for export/import/push actions.
func DojoAudit(ctx context.Context, db DojoDB, userID *int64, action, entity string, details any) error {
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `INSERT INTO audit_log (user_id, action, entity, details) VALUES ($1, $2, $3, $4)`,
		userID, action, entity, b)
	return err
}
