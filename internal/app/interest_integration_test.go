//go:build integration

package app

import (
	"context"
	"os"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/db"
)

// TestInterestQueries checks that ListServices, GetService and the
// dashboard compute the interest score from the stored data. The database
// in ASI_TEST_DATABASE_URL is wiped: never point it at real data.
func TestInterestQueries(t *testing.T) {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `TRUNCATE scan_runs, host_state, annotations, changes, diff_runs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var run int64
	if err := pool.QueryRow(ctx, `INSERT INTO scan_runs (status, started_at, finished_at) VALUES ('done', now(), now()) RETURNING id`).Scan(&run); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO host_obs (run_id, ip, up) VALUES ($1, '10.0.0.1', true), ($1, '10.0.0.2', true), ($1, '10.0.0.3', true)`, run)
	exec(`INSERT INTO services (run_id, ip, port, proto, banner, product) VALUES
		($1, '10.0.0.1', 80, 'tcp', 'http', 'nginx'),
		($1, '10.0.0.2', 80, 'tcp', 'http', 'Apache httpd'),
		($1, '10.0.0.3', 15432, 'tcp', 'postgresql', 'PostgreSQL DB')`, run)
	// 1: plain nginx; 2: outdated WordPress with an admin panel over HTTP,
	// expired certificate; 3: PostgreSQL on a non-standard port, new.
	exec(`INSERT INTO http_obs (service_id, url, tls) VALUES (1, 'http://10.0.0.1/', NULL),
		(2, 'http://10.0.0.2/', '{"expired": true, "self_signed": false}')`)
	exec(`INSERT INTO detections (service_id, signature_id, name, category, confidence, evidence) VALUES
		(1, 'nginx', 'nginx', 'server', 85, '{}'),
		(2, 'wordpress', 'WordPress', 'cms', 90, '{"outdated": "version 4.7 < 6.0", "severity": "High"}'),
		(2, 'admin-panel', 'Panel', 'admin-panel', 80, '{}')`)
	exec(`INSERT INTO changes (run_id, kind, ip, port, proto) VALUES ($1, 'new', '10.0.0.3', 15432, 'tcp')`, run)

	rows, err := ListServices(ctx, pool, ResultFilter{RunID: run})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].ID != 1 {
		t.Fatalf("default order changed: %+v", rows)
	}
	score := map[int64]int{}
	for _, r := range rows {
		score[r.ID] = r.Interest.Score
	}
	// WordPress: 45*90/100=40 + admin 20 + cms 5 + outdated 15 + expired 10 + login over http 10 = 100
	// PostgreSQL: database 20 + new 15 = 35; nginx: 0
	if score[2] != 100 || score[3] != 35 || score[1] != 0 {
		t.Fatalf("scores = %v (%+v)", score, rows)
	}

	rows, err = ListServices(ctx, pool, ResultFilter{RunID: run, Sort: "priority"})
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].ID != 2 || rows[1].ID != 3 || rows[2].ID != 1 {
		t.Fatalf("priority order = %d %d %d", rows[0].ID, rows[1].ID, rows[2].ID)
	}

	d, err := LoadDashboard(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.TopInterest) != 2 || d.TopInterest[0].ID != 2 {
		t.Fatalf("TopInterest = %+v", d.TopInterest)
	}

	s, err := GetService(ctx, pool, 3)
	if err != nil {
		t.Fatal(err)
	}
	if s.Interest.Score != 35 {
		t.Fatalf("service page score = %+v", s.Interest)
	}

	// an analyst false positive drops the score to 0
	exec(`INSERT INTO annotations (ip, port, proto, vhost, false_positive) VALUES ('10.0.0.2', 80, 'tcp', '', true)`)
	if s, err = GetService(ctx, pool, 2); err != nil {
		t.Fatal(err)
	}
	if s.Interest.Score != 0 || s.Interest.Level != "brak" {
		t.Fatalf("false positive score = %+v", s.Interest)
	}
}
