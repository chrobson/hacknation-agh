//go:build integration

package db_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/db"
)

// Two processes migrating a fresh database at once (the app starting while
// `asi seed-demo` runs) must not collide on CREATE TABLE.
// ASI_TEST_DATABASE_URL must point at an empty database.
func TestMigrateConcurrent(t *testing.T) {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pool, err := db.Open(ctx, url)
			if err != nil {
				errs[i] = err
				return
			}
			defer pool.Close()
			_, errs[i] = db.Migrate(ctx, pool)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("migrate %d: %v", i, err)
		}
	}
}
