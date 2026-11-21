// This file: read-only history views over finished scan runs (change
// timeline, per-asset presence and history). Nothing here writes.
package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// lastScanRuns is a CTE body selecting the newest $1 finished scan runs.
// Imports never count: they carry only the hosts present in the file.
const lastScanRuns = `SELECT id, coalesce(started_at, finished_at, 'epoch'::timestamptz) AS started_at
	FROM scan_runs WHERE kind = 'scan' AND status = 'done' ORDER BY id DESC LIMIT $1`

// covers is a SQL predicate: run r has a finished chunk containing address col.
func covers(col string) string {
	return `EXISTS (SELECT 1 FROM scan_chunks c WHERE c.run_id = r.id AND c.status = 'done' AND c.cidr >>= ` + col + `)`
}

// RunPoint summarises one finished scan run for the change timeline.
type RunPoint struct {
	RunID      int64
	StartedAt  time.Time
	FinishedAt time.Time
	HostsUp    int
	Services   int
	Counts     map[model.ChangeKind]int
}

// RunSeries returns the newest limit finished scan runs, oldest first.
func RunSeries(ctx context.Context, db DiffDB, limit int) ([]RunPoint, error) {
	rows, err := db.Query(ctx, `
		WITH r AS (SELECT id, started_at, finished_at FROM scan_runs
		           WHERE kind = 'scan' AND status = 'done' ORDER BY id DESC LIMIT $1)
		SELECT r.id, coalesce(r.started_at, r.finished_at, 'epoch'::timestamptz),
		       coalesce(r.finished_at, r.started_at, 'epoch'::timestamptz),
		       (SELECT count(*) FROM host_obs h WHERE h.run_id = r.id AND h.up),
		       (SELECT count(*) FROM services s WHERE s.run_id = r.id),
		       coalesce((SELECT jsonb_object_agg(kind, n) FROM
		           (SELECT kind, count(*) AS n FROM changes c WHERE c.run_id = r.id GROUP BY kind) k), '{}')
		FROM r ORDER BY r.id`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunPoint
	for rows.Next() {
		var p RunPoint
		var counts []byte
		if err := rows.Scan(&p.RunID, &p.StartedAt, &p.FinishedAt, &p.HostsUp, &p.Services, &counts); err != nil {
			return nil, err
		}
		raw := map[string]int{}
		if err := json.Unmarshal(counts, &raw); err != nil {
			return nil, err
		}
		p.Counts = make(map[model.ChangeKind]int, len(raw))
		for k, n := range raw {
			p.Counts[model.ChangeKind(k)] = n
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Presence is one covering run of an asset and whether the asset was seen.
type Presence struct {
	RunID     int64
	StartedAt time.Time
	Seen      bool
}

// AssetPresence lists the covering runs of one asset, oldest first.
type AssetPresence struct {
	Key     model.AssetKey
	Samples []Presence
}

// HostPresence returns, for every known host (host_state), the newest
// lastRuns finished scan runs that covered it (a done chunk containing the
// address) and whether the host answered (host_obs.up). Hosts not covered by
// any of those runs are omitted.
func HostPresence(ctx context.Context, db DiffDB, lastRuns int) ([]AssetPresence, error) {
	rows, err := db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`)
		SELECT host(hs.ip), 0, '', '', r.id, r.started_at, coalesce(h.up, false)
		FROM host_state hs CROSS JOIN r
		LEFT JOIN host_obs h ON h.run_id = r.id AND h.ip = hs.ip
		WHERE `+covers("hs.ip")+`
		ORDER BY hs.ip, r.id`, lastRuns)
	if err != nil {
		return nil, err
	}
	return scanPresence(rows)
}

// ServicePresence is HostPresence for every service key (ip, port, proto,
// vhost) observed in at least one of the newest lastRuns finished scan runs.
func ServicePresence(ctx context.Context, db DiffDB, lastRuns int) ([]AssetPresence, error) {
	rows, err := db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`),
		k AS (SELECT DISTINCT ip, port, proto, vhost FROM services WHERE run_id IN (SELECT id FROM r))
		SELECT host(k.ip), k.port, k.proto, k.vhost, r.id, r.started_at,
		       EXISTS (SELECT 1 FROM services s WHERE s.run_id = r.id AND s.ip = k.ip
		               AND s.port = k.port AND s.proto = k.proto AND s.vhost = k.vhost)
		FROM k CROSS JOIN r
		WHERE `+covers("k.ip")+`
		ORDER BY k.ip, k.port, k.proto, k.vhost, r.id`, lastRuns)
	if err != nil {
		return nil, err
	}
	return scanPresence(rows)
}

func scanPresence(rows pgx.Rows) ([]AssetPresence, error) {
	defer rows.Close()
	var out []AssetPresence
	for rows.Next() {
		var k model.AssetKey
		var ip string
		var port int
		var p Presence
		if err := rows.Scan(&ip, &port, &k.Proto, &k.VHost, &p.RunID, &p.StartedAt, &p.Seen); err != nil {
			return nil, err
		}
		var err error
		if k.IP, err = parseAddr(ip); err != nil {
			return nil, err
		}
		k.Port = uint16(port)
		if n := len(out); n == 0 || out[n-1].Key != k {
			out = append(out, AssetPresence{Key: k})
		}
		out[len(out)-1].Samples = append(out[len(out)-1].Samples, p)
	}
	return out, rows.Err()
}

// AssetRun is one finished scan run on an asset's history page.
type AssetRun struct {
	RunID      int64
	StartedAt  time.Time
	Covered    bool // a done chunk of the run contains the address
	Seen       bool
	Product    string
	Version    string
	HTTPStatus int
	HTTPTitle  string
}

// AssetTimeline is the per-run history and the recorded changes of one key.
type AssetTimeline struct {
	Key     model.AssetKey
	Runs    []AssetRun // oldest first
	Changes []model.Change
}

// maxHistoryChanges caps the change list of one key.
const maxHistoryChanges = 500

// AssetHistory loads the newest lastRuns finished scan runs as seen from
// key (port 0 = host: seen means host_obs.up) and the key's changes.
func AssetHistory(ctx context.Context, db DiffDB, key model.AssetKey, lastRuns int) (AssetTimeline, error) {
	h := AssetTimeline{Key: key}
	ip := key.IP.Unmap().String()
	rows, err := db.Query(ctx, `
		WITH r AS (`+lastScanRuns+`)
		SELECT r.id, r.started_at, `+covers("$2::inet")+`,
		       CASE WHEN $3::int = 0
		            THEN coalesce((SELECT up FROM host_obs h WHERE h.run_id = r.id AND h.ip = $2::inet), false)
		            ELSE s.id IS NOT NULL END,
		       coalesce(s.product, ''), coalesce(s.version, ''), coalesce(ho.status, 0), coalesce(ho.title, '')
		FROM r
		LEFT JOIN services s ON $3::int <> 0 AND s.run_id = r.id AND s.ip = $2::inet
		     AND s.port = $3::int AND s.proto = $4::text AND s.vhost = $5::text
		LEFT JOIN http_obs ho ON ho.service_id = s.id
		ORDER BY r.id`, lastRuns, ip, int(key.Port), key.Proto, key.VHost)
	if err != nil {
		return h, err
	}
	defer rows.Close()
	for rows.Next() {
		var a AssetRun
		if err := rows.Scan(&a.RunID, &a.StartedAt, &a.Covered, &a.Seen, &a.Product, &a.Version,
			&a.HTTPStatus, &a.HTTPTitle); err != nil {
			return h, err
		}
		h.Runs = append(h.Runs, a)
	}
	if err := rows.Err(); err != nil {
		return h, err
	}
	rows.Close()

	crows, err := db.Query(ctx, `
		SELECT run_id, coalesce(prev_run_id, 0), kind, field, old, new
		FROM changes WHERE ip = $1::inet AND port = $2 AND proto = $3 AND vhost = $4
		ORDER BY run_id DESC, id LIMIT $5`, ip, int(key.Port), key.Proto, key.VHost, maxHistoryChanges)
	if err != nil {
		return h, err
	}
	defer crows.Close()
	for crows.Next() {
		c := model.Change{Key: key}
		var kind string
		if err := crows.Scan(&c.RunID, &c.PrevRunID, &kind, &c.Field, &c.Old, &c.New); err != nil {
			return h, err
		}
		c.Kind = model.ChangeKind(kind)
		h.Changes = append(h.Changes, c)
	}
	return h, crows.Err()
}
