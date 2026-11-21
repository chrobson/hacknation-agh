// Package store holds plain pgx queries, one file per module.
package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// DBTX is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
}

// ErrTargetNotFound is returned when a target id does not exist.
var ErrTargetNotFound = errors.New("target not found")

const targetCols = `id, kind, value, tags`

func scanTargets(rows pgx.Rows) ([]model.Target, error) {
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

// ListTargets returns all targets ordered by kind and value, optionally only
// those carrying tag (empty = all).
func ListTargets(ctx context.Context, q DBTX, tag string) ([]model.Target, error) {
	var rows pgx.Rows
	var err error
	if tag == "" {
		rows, err = q.Query(ctx, `SELECT `+targetCols+` FROM targets ORDER BY kind, value`)
	} else {
		rows, err = q.Query(ctx, `SELECT `+targetCols+` FROM targets WHERE tags @> ARRAY[$1]::text[] ORDER BY kind, value`, tag)
	}
	if err != nil {
		return nil, err
	}
	return scanTargets(rows)
}

// TargetsByIDs returns the targets with the given ids (missing ids are skipped).
func TargetsByIDs(ctx context.Context, q DBTX, ids []int64) ([]model.Target, error) {
	rows, err := q.Query(ctx, `SELECT `+targetCols+` FROM targets WHERE id = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, err
	}
	return scanTargets(rows)
}

// TargetTags returns all distinct tags in use, sorted.
func TargetTags(ctx context.Context, q DBTX) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT unnest(tags) AS t FROM targets ORDER BY t`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// InsertTargets inserts targets, skipping values that already exist, and
// returns how many rows were inserted. createdBy may be nil. Run it inside a
// transaction when the whole import must be atomic.
func InsertTargets(ctx context.Context, q DBTX, ts []model.Target, createdBy *int64) (int, error) {
	if len(ts) == 0 {
		return 0, nil
	}
	b := &pgx.Batch{}
	for _, t := range ts {
		tags := t.Tags
		if tags == nil {
			tags = []string{}
		}
		b.Queue(`INSERT INTO targets (kind, value, tags, created_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (value) DO NOTHING`, string(t.Kind), t.Value, tags, createdBy)
	}
	br := q.SendBatch(ctx, b)
	inserted := 0
	for range ts {
		tag, err := br.Exec()
		if err != nil {
			_ = br.Close()
			return inserted, err
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, br.Close()
}

// UpdateTargetTags replaces the tags of one target.
func UpdateTargetTags(ctx context.Context, q DBTX, id int64, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	tag, err := q.Exec(ctx, `UPDATE targets SET tags = $2 WHERE id = $1`, id, tags)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTargetNotFound
	}
	return nil
}

// DeleteTarget removes one target and returns its value. Scan configs keep
// stale ids in target_ids; TargetsByIDs skips them.
func DeleteTarget(ctx context.Context, q DBTX, id int64) (string, error) {
	var value string
	err := q.QueryRow(ctx, `DELETE FROM targets WHERE id = $1 RETURNING value`, id).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTargetNotFound
	}
	return value, err
}

// AuditTargets writes an audit_log row for a targets action.
func AuditTargets(ctx context.Context, q DBTX, userID *int64, action string, details any) error {
	js, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_log (user_id, action, entity, details) VALUES ($1, $2, 'targets', $3)`,
		userID, action, js)
	return err
}
