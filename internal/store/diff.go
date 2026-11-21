// Package store holds plain pgx queries. This file: diff, host state and
// annotations (W1-4).
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

	"github.com/chrobson/hacknation-agh/internal/model"
)

// DiffDB is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type DiffDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrAnnotationNotFound is returned when no annotation exists for a key.
var ErrAnnotationNotFound = errors.New("annotation not found")

// Inet values are passed and read as text (host(ip)) so netip.Addr round-trips
// without depending on pgx's inet codec.

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse ip %q: %w", s, err)
	}
	return a.Unmap(), nil
}

// ---------------------------------------------------------------- runs ---

// DiffPrevRunID returns the newest finished scan run (kind 'scan') older
// than runID, or 0. Import runs are never used as a baseline: they carry a
// partial view (only the hosts in the file, fewer fields) and would make the
// next scan report everything else as changed or gone.
func DiffPrevRunID(ctx context.Context, db DiffDB, runID int64) (int64, error) {
	var id *int64
	err := db.QueryRow(ctx,
		`SELECT max(id) FROM scan_runs WHERE id < $1 AND status = 'done' AND kind = 'scan'`, runID).Scan(&id)
	if err != nil || id == nil {
		return 0, err
	}
	return *id, nil
}

// DiffRunApplied reports whether the diff of runID has already been applied.
func DiffRunApplied(ctx context.Context, db DiffDB, runID int64) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM diff_runs WHERE run_id = $1)`, runID).Scan(&ok)
	return ok, err
}

// DiffMarkApplied records that runID's diff was applied against prevRunID.
func DiffMarkApplied(ctx context.Context, db DiffDB, runID, prevRunID int64, changes int) error {
	_, err := db.Exec(ctx,
		`INSERT INTO diff_runs (run_id, prev_run_id, changes) VALUES ($1, NULLIF($2::bigint, 0), $3)`,
		runID, prevRunID, changes)
	return err
}

// DiffLockRuns serialises diff application within a transaction.
func DiffLockRuns(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(4000001)`)
	return err
}

// DiffRunServices loads all services observed in a run.
func DiffRunServices(ctx context.Context, db DiffDB, runID int64) ([]model.ServiceObs, error) {
	return DiffRunServicesInScope(ctx, db, runID, runID)
}

// DiffRunIsImport reports whether runID is an import run.
func DiffRunIsImport(ctx context.Context, db DiffDB, runID int64) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scan_runs WHERE id = $1 AND kind = 'import')`, runID).Scan(&ok)
	return ok, err
}

// inScope is a SQL predicate: address column col lies in the scope of the run
// given by parameter p. An import run covers exactly the hosts present in the
// file (its host_obs and services); a scan run covers its chunk CIDRs; a scan
// run without chunks covers everything.
func inScope(col, p string) string {
	return `(CASE WHEN EXISTS (SELECT 1 FROM scan_runs r WHERE r.id = ` + p + ` AND r.kind = 'import') THEN
		   EXISTS (SELECT 1 FROM host_obs h WHERE h.run_id = ` + p + ` AND h.ip = ` + col + `)
		   OR EXISTS (SELECT 1 FROM services s2 WHERE s2.run_id = ` + p + ` AND s2.ip = ` + col + `)
		 ELSE NOT EXISTS (SELECT 1 FROM scan_chunks c WHERE c.run_id = ` + p + `)
		   OR EXISTS (SELECT 1 FROM scan_chunks c WHERE c.run_id = ` + p + ` AND ` + col + ` <<= c.cidr) END)`
}

// DiffRunServicesInScope loads the services of runID restricted to the scope
// of scopeRunID (see inScope). Used to load the previous run's services
// without reporting hosts outside the current run's targets as gone.
func DiffRunServicesInScope(ctx context.Context, db DiffDB, runID, scopeRunID int64) ([]model.ServiceObs, error) {
	rows, err := db.Query(ctx, `
		SELECT id, run_id, host(ip), port, proto, vhost, product, version, extrainfo, cpe, banner
		FROM services s WHERE run_id = $1 AND `+inScope("s.ip", "$2"),
		runID, scopeRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ServiceObs
	for rows.Next() {
		var s model.ServiceObs
		var ip string
		var port int
		if err := rows.Scan(&s.ID, &s.RunID, &ip, &port, &s.Key.Proto, &s.Key.VHost,
			&s.Product, &s.Version, &s.ExtraInfo, &s.CPE, &s.Banner); err != nil {
			return nil, err
		}
		if s.Key.IP, err = parseAddr(ip); err != nil {
			return nil, err
		}
		s.Key.Port = uint16(port)
		out = append(out, s)
	}
	return out, rows.Err()
}

// DiffRunHostObs loads the host observations of a run.
func DiffRunHostObs(ctx context.Context, db DiffDB, runID int64) ([]model.HostObs, error) {
	rows, err := db.Query(ctx, `SELECT run_id, host(ip), hostname, up FROM host_obs WHERE run_id = $1`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.HostObs
	for rows.Next() {
		var h model.HostObs
		var ip string
		if err := rows.Scan(&h.RunID, &ip, &h.Hostname, &h.Up); err != nil {
			return nil, err
		}
		if h.IP, err = parseAddr(ip); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------- host state ---

const hostStateCols = `host(ip), state, misses, flips, first_seen, last_seen`

func scanHostStates(rows pgx.Rows) ([]model.HostState, error) {
	defer rows.Close()
	var out []model.HostState
	for rows.Next() {
		var h model.HostState
		var ip, state string
		var flips []byte
		if err := rows.Scan(&ip, &state, &h.Misses, &flips, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, err
		}
		var err error
		if h.IP, err = parseAddr(ip); err != nil {
			return nil, err
		}
		h.State = model.HostStateKind(state)
		if err := json.Unmarshal(flips, &h.Flips); err != nil {
			return nil, fmt.Errorf("host_state %s flips: %w", ip, err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DiffHostStatesInScope returns (and, in a transaction, locks) the states of
// known hosts covered by runID (see inScope): hosts inside one of a scan
// run's chunk CIDRs, only the hosts present in an import, or every known host
// for a scan run without chunks.
func DiffHostStatesInScope(ctx context.Context, db DiffDB, runID int64) ([]model.HostState, error) {
	rows, err := db.Query(ctx, `
		SELECT `+hostStateCols+` FROM host_state hs
		WHERE `+inScope("hs.ip", "$1")+`
		ORDER BY hs.ip
		FOR UPDATE OF hs`, runID)
	if err != nil {
		return nil, err
	}
	return scanHostStates(rows)
}

// ListHostStates returns all known hosts, optionally filtered by state.
func ListHostStates(ctx context.Context, db DiffDB, state string) ([]model.HostState, error) {
	rows, err := db.Query(ctx, `
		SELECT `+hostStateCols+` FROM host_state
		WHERE $1 = '' OR state = $1 ORDER BY ip`, state)
	if err != nil {
		return nil, err
	}
	return scanHostStates(rows)
}

// HostStateCounts returns the number of hosts per state.
func HostStateCounts(ctx context.Context, db DiffDB) (map[model.HostStateKind]int, error) {
	rows, err := db.Query(ctx, `SELECT state, count(*) FROM host_state GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.HostStateKind]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[model.HostStateKind(s)] = n
	}
	return out, rows.Err()
}

// SaveHostStates upserts host states.
func SaveHostStates(ctx context.Context, db DiffDB, hs []model.HostState) error {
	for _, h := range hs {
		flips := h.Flips
		if flips == nil {
			flips = []model.Flip{}
		}
		fj, err := json.Marshal(flips)
		if err != nil {
			return err
		}
		first, last := h.FirstSeen, h.LastSeen
		if first.IsZero() {
			first = time.Now()
		}
		if last.IsZero() {
			last = first
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO host_state (ip, state, misses, flips, first_seen, last_seen)
			VALUES ($1::inet, $2, $3, $4::jsonb, $5, $6)
			ON CONFLICT (ip) DO UPDATE SET state = EXCLUDED.state, misses = EXCLUDED.misses,
				flips = EXCLUDED.flips, last_seen = EXCLUDED.last_seen`,
			h.IP.Unmap().String(), string(h.State), h.Misses, string(fj), first, last); err != nil {
			return fmt.Errorf("save host_state %s: %w", h.IP, err)
		}
	}
	return nil
}

// ------------------------------------------------------------- changes ---

// InsertChanges stores changes in one statement.
func InsertChanges(ctx context.Context, tx pgx.Tx, cs []model.Change) error {
	if len(cs) == 0 {
		return nil
	}
	// COPY cannot cast text to inet, so insert via unnest of parallel arrays.
	var (
		run, prev           []int64
		kind, ip, proto, vh []string
		field, old, nw      []string
		port                []int32
	)
	for _, c := range cs {
		run = append(run, c.RunID)
		prev = append(prev, c.PrevRunID)
		kind = append(kind, string(c.Kind))
		ip = append(ip, c.Key.IP.Unmap().String())
		port = append(port, int32(c.Key.Port))
		proto = append(proto, c.Key.Proto)
		vh = append(vh, c.Key.VHost)
		field = append(field, c.Field)
		old = append(old, c.Old)
		nw = append(nw, c.New)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO changes (run_id, prev_run_id, kind, ip, port, proto, vhost, field, old, new)
		SELECT r, NULLIF(p, 0), k, i::inet, po, pr, v, f, o, n
		FROM unnest($1::bigint[], $2::bigint[], $3::text[], $4::text[], $5::int[], $6::text[],
		            $7::text[], $8::text[], $9::text[], $10::text[])
		     AS t(r, p, k, i, po, pr, v, f, o, n)`,
		run, prev, kind, ip, port, proto, vh, field, old, nw)
	return err
}

// DiffServiceFlips counts, per service key, the new/gone changes recorded in
// the last n diffed scan runs before runID (imports excluded). Keys without
// any such change are absent from the result.
func DiffServiceFlips(ctx context.Context, db DiffDB, runID int64, keys []model.AssetKey, n int) (map[model.AssetKey]int, error) {
	out := map[model.AssetKey]int{}
	if len(keys) == 0 || n <= 0 {
		return out, nil
	}
	var ip, proto, vh []string
	var port []int32
	for _, k := range keys {
		ip = append(ip, k.IP.Unmap().String())
		port = append(port, int32(k.Port))
		proto = append(proto, k.Proto)
		vh = append(vh, k.VHost)
	}
	rows, err := db.Query(ctx, `
		WITH runs AS (
			SELECT d.run_id FROM diff_runs d JOIN scan_runs r ON r.id = d.run_id
			WHERE r.kind = 'scan' AND d.run_id < $1
			ORDER BY d.run_id DESC LIMIT $2
		), k AS (
			SELECT i::inet AS ip, po AS port, pr AS proto, v AS vhost
			FROM unnest($3::text[], $4::int[], $5::text[], $6::text[]) AS t(i, po, pr, v)
		)
		SELECT host(c.ip), c.port, c.proto, c.vhost, count(*)
		FROM changes c JOIN k ON c.ip = k.ip AND c.port = k.port AND c.proto = k.proto AND c.vhost = k.vhost
		WHERE c.run_id IN (SELECT run_id FROM runs) AND c.kind IN ('new', 'gone')
		GROUP BY 1, 2, 3, 4`,
		runID, n, ip, port, proto, vh)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k model.AssetKey
		var a string
		var p, cnt int
		if err := rows.Scan(&a, &p, &k.Proto, &k.VHost, &cnt); err != nil {
			return nil, err
		}
		if k.IP, err = parseAddr(a); err != nil {
			return nil, err
		}
		k.Port = uint16(p)
		out[k] = cnt
	}
	return out, rows.Err()
}

// ListChanges returns the changes of one run ordered by key.
func ListChanges(ctx context.Context, db DiffDB, runID int64) ([]model.Change, error) {
	rows, err := db.Query(ctx, `
		SELECT run_id, coalesce(prev_run_id, 0), kind, host(ip), port, proto, vhost, field, old, new
		FROM changes WHERE run_id = $1 ORDER BY ip, port, proto, vhost, id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Change
	for rows.Next() {
		var c model.Change
		var kind, ip string
		var port int
		if err := rows.Scan(&c.RunID, &c.PrevRunID, &kind, &ip, &port, &c.Key.Proto, &c.Key.VHost,
			&c.Field, &c.Old, &c.New); err != nil {
			return nil, err
		}
		if c.Key.IP, err = parseAddr(ip); err != nil {
			return nil, err
		}
		c.Kind = model.ChangeKind(kind)
		c.Key.Port = uint16(port)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ChangeRun summarises one run on the changes overview.
type ChangeRun struct {
	RunID      int64
	PrevRunID  int64
	Kind       string // scan | import
	Status     string
	StartedAt  *time.Time
	FinishedAt *time.Time
	Applied    bool
	Counts     map[model.ChangeKind]int
	Total      int
}

// ListChangeRuns returns the newest runs with change counts per kind.
func ListChangeRuns(ctx context.Context, db DiffDB, limit int) ([]ChangeRun, error) {
	rows, err := db.Query(ctx, `
		SELECT r.id, coalesce(d.prev_run_id, 0), r.kind, r.status, r.started_at, r.finished_at,
		       d.run_id IS NOT NULL,
		       coalesce((SELECT jsonb_object_agg(kind, n) FROM
		           (SELECT kind, count(*) AS n FROM changes c WHERE c.run_id = r.id GROUP BY kind) k), '{}')
		FROM scan_runs r LEFT JOIN diff_runs d ON d.run_id = r.id
		ORDER BY r.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeRun
	for rows.Next() {
		var cr ChangeRun
		var counts []byte
		if err := rows.Scan(&cr.RunID, &cr.PrevRunID, &cr.Kind, &cr.Status, &cr.StartedAt, &cr.FinishedAt,
			&cr.Applied, &counts); err != nil {
			return nil, err
		}
		raw := map[string]int{}
		if err := json.Unmarshal(counts, &raw); err != nil {
			return nil, err
		}
		cr.Counts = make(map[model.ChangeKind]int, len(raw))
		for k, n := range raw {
			cr.Counts[model.ChangeKind(k)] = n
			cr.Total += n
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}

// GetChangeRun returns the summary of one run, or pgx.ErrNoRows.
func GetChangeRun(ctx context.Context, db DiffDB, runID int64) (ChangeRun, error) {
	var cr ChangeRun
	err := db.QueryRow(ctx, `
		SELECT r.id, coalesce(d.prev_run_id, 0), r.kind, r.status, r.started_at, r.finished_at,
		       d.run_id IS NOT NULL
		FROM scan_runs r LEFT JOIN diff_runs d ON d.run_id = r.id WHERE r.id = $1`, runID).
		Scan(&cr.RunID, &cr.PrevRunID, &cr.Kind, &cr.Status, &cr.StartedAt, &cr.FinishedAt, &cr.Applied)
	return cr, err
}

// --------------------------------------------------------- annotations ---

// Annotation is an analyst edit keyed by the natural asset key. It lives
// independently of scan runs, so it survives rescans. Port 0 = host level.
type Annotation struct {
	Key           model.AssetKey
	Comment       string
	Tags          []string
	Severity      string // "" = not set; otherwise a model.Severity value
	FalsePositive bool
	UpdatedBy     int64 // 0 = unknown
	UpdatedAt     time.Time
}

const annotationCols = `host(ip), port, proto, vhost, comment, tags, coalesce(severity, ''),
	false_positive, coalesce(updated_by, 0), updated_at`

func scanAnnotation(row pgx.Row) (Annotation, error) {
	var a Annotation
	var ip string
	var port int
	if err := row.Scan(&ip, &port, &a.Key.Proto, &a.Key.VHost, &a.Comment, &a.Tags, &a.Severity,
		&a.FalsePositive, &a.UpdatedBy, &a.UpdatedAt); err != nil {
		return a, err
	}
	var err error
	a.Key.IP, err = parseAddr(ip)
	a.Key.Port = uint16(port)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return a, err
}

// GetAnnotation returns the annotation of a key or ErrAnnotationNotFound.
func GetAnnotation(ctx context.Context, db DiffDB, k model.AssetKey) (Annotation, error) {
	a, err := scanAnnotation(db.QueryRow(ctx, `SELECT `+annotationCols+` FROM annotations
		WHERE ip = $1::inet AND port = $2 AND proto = $3 AND vhost = $4`,
		k.IP.Unmap().String(), int(k.Port), k.Proto, k.VHost))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrAnnotationNotFound
	}
	return a, err
}

// ListAnnotations returns annotations, optionally only those of one IP.
func ListAnnotations(ctx context.Context, db DiffDB, ip netip.Addr) ([]Annotation, error) {
	var ipArg *string // NULL = all hosts; avoids casting '' to inet
	if ip.IsValid() {
		s := ip.Unmap().String()
		ipArg = &s
	}
	rows, err := db.Query(ctx, `SELECT `+annotationCols+` FROM annotations
		WHERE $1::inet IS NULL OR ip = $1::inet ORDER BY ip, port, proto, vhost`, ipArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Annotation
	for rows.Next() {
		a, err := scanAnnotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AnnotationsByIPs returns annotations of the given hosts (all ports),
// keyed by asset key, for showing next to services and changes.
func AnnotationsByIPs(ctx context.Context, db DiffDB, ips []netip.Addr) (map[model.AssetKey]Annotation, error) {
	out := map[model.AssetKey]Annotation{}
	if len(ips) == 0 {
		return out, nil
	}
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.Unmap().String()
	}
	rows, err := db.Query(ctx, `SELECT `+annotationCols+` FROM annotations
		WHERE ip = ANY($1::inet[])`, strs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		a, err := scanAnnotation(rows)
		if err != nil {
			return nil, err
		}
		out[a.Key] = a
	}
	return out, rows.Err()
}

// UpsertAnnotation creates or replaces the annotation of a.Key and writes an
// audit_log entry.
func UpsertAnnotation(ctx context.Context, db DiffDB, a Annotation) (Annotation, error) {
	tags := a.Tags
	if tags == nil {
		tags = []string{}
	}
	k := a.Key
	out, err := scanAnnotation(db.QueryRow(ctx, `
		INSERT INTO annotations (ip, port, proto, vhost, comment, tags, severity, false_positive, updated_by, updated_at)
		VALUES ($1::inet, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, NULLIF($9::bigint, 0), now())
		ON CONFLICT (ip, port, proto, vhost) DO UPDATE SET
			comment = EXCLUDED.comment, tags = EXCLUDED.tags, severity = EXCLUDED.severity,
			false_positive = EXCLUDED.false_positive, updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
		RETURNING `+annotationCols,
		k.IP.Unmap().String(), int(k.Port), k.Proto, k.VHost, a.Comment, tags, a.Severity,
		a.FalsePositive, a.UpdatedBy))
	if err != nil {
		return out, err
	}
	return out, annotationAudit(ctx, db, "annotation.upsert", a.UpdatedBy, k)
}

// DeleteAnnotation removes the annotation of k; ErrAnnotationNotFound if none.
func DeleteAnnotation(ctx context.Context, db DiffDB, k model.AssetKey, userID int64) error {
	tag, err := db.Exec(ctx, `DELETE FROM annotations
		WHERE ip = $1::inet AND port = $2 AND proto = $3 AND vhost = $4`,
		k.IP.Unmap().String(), int(k.Port), k.Proto, k.VHost)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAnnotationNotFound
	}
	return annotationAudit(ctx, db, "annotation.delete", userID, k)
}

func annotationAudit(ctx context.Context, db DiffDB, action string, userID int64, k model.AssetKey) error {
	details, _ := json.Marshal(map[string]any{
		"ip": k.IP.Unmap().String(), "port": k.Port, "proto": k.Proto, "vhost": k.VHost,
	})
	_, err := db.Exec(ctx, `INSERT INTO audit_log (user_id, action, entity, details)
		VALUES (NULLIF($1::bigint, 0), $2, 'annotation', $3::jsonb)`, userID, action, string(details))
	return err
}
