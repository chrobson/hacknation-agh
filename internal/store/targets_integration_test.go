//go:build integration

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/model"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestTargetsStore(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	// Unique per run so tests can share a database.
	tag := fmt.Sprintf("it-%d", time.Now().UnixNano())
	base := fmt.Sprintf("192.0.2.%d", time.Now().UnixNano()%200)
	ts := []model.Target{
		{Kind: model.TargetIP, Value: base, Tags: []string{tag, "lab"}},
		{Kind: model.TargetDomain, Value: tag + ".lab.test", Tags: []string{tag}},
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM targets WHERE tags @> ARRAY[$1]::text[]`, tag)
	})

	var n int
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		n, err = InsertTargets(ctx, tx, ts, nil)
		if err != nil {
			return err
		}
		return AuditTargets(ctx, tx, nil, "targets.import", map[string]int{"inserted": n})
	})
	if err != nil || n != 2 {
		t.Fatalf("insert: n=%d err=%v", n, err)
	}
	if n, err = InsertTargets(ctx, pool, ts, nil); err != nil || n != 0 {
		t.Fatalf("re-insert must skip duplicates: n=%d err=%v", n, err)
	}

	got, err := ListTargets(ctx, pool, tag)
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %+v %v", got, err)
	}
	if got[0].Kind != model.TargetDomain || got[1].Value != base {
		t.Errorf("order/kind: %+v", got)
	}
	tags, err := TargetTags(ctx, pool)
	if err != nil || !slices.Contains(tags, tag) {
		t.Errorf("tags: %v %v", tags, err)
	}

	id := got[1].ID
	if err := UpdateTargetTags(ctx, pool, id, []string{tag, "edited"}); err != nil {
		t.Fatal(err)
	}
	byID, err := TargetsByIDs(ctx, pool, []int64{id, -1})
	if err != nil || len(byID) != 1 || !slices.Contains(byID[0].Tags, "edited") {
		t.Fatalf("by ids: %+v %v", byID, err)
	}
	if v, err := DeleteTarget(ctx, pool, id); err != nil || v != base {
		t.Fatalf("delete: %q %v", v, err)
	}
	if _, err := DeleteTarget(ctx, pool, id); !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if err := UpdateTargetTags(ctx, pool, id, nil); !errors.Is(err, ErrTargetNotFound) {
		t.Errorf("update missing: %v", err)
	}
}
