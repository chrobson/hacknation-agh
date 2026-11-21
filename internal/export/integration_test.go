//go:build integration

package export

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// TestImportExportDB imports the nmap fixture and the golden Generic
// Findings file, then exports them again, all inside one rolled-back
// transaction.
func TestImportExportDB(t *testing.T) {
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
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	nmapRun := importFile(ctx, t, tx, "../../testdata/dojo/nmap_sample.xml")
	svcs, err := store.ExportServices(ctx, tx, nmapRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 4 {
		t.Fatalf("nmap import: %d services", len(svcs))
	}
	if svcs[0].Hostname != "web.lab.test" {
		t.Errorf("hostname %q", svcs[0].Hostname)
	}

	genRun := importFile(ctx, t, tx, "../../testdata/dojo/golden_findings.json")
	run, err := store.ExportRunByID(ctx, tx, genRun)
	if err != nil || run.ID != genRun || run.Kind != "import" {
		t.Fatalf("import run %+v %v", run, err)
	}
	// The latest run is a scan whenever one exists; imports only otherwise.
	var scans int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM scan_runs WHERE kind='scan' AND status='done'`).Scan(&scans); err != nil {
		t.Fatal(err)
	}
	latest, err := store.ExportLatestRun(ctx, tx)
	if err != nil || (scans > 0) != (latest.Kind == "scan") || (scans == 0 && latest.ID != genRun) {
		t.Fatalf("latest run %+v %v (scans: %d)", latest, err, scans)
	}
	svcs, err = store.ExportServices(ctx, tx, genRun)
	if err != nil {
		t.Fatal(err)
	}
	dets := 0
	for _, s := range svcs {
		dets += len(s.Detections)
	}
	if len(svcs) != 5 || dets != 3 {
		t.Fatalf("generic import: %d services, %d detections", len(svcs), dets)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO annotations (ip, port, proto, vhost, false_positive)
		VALUES ('10.20.0.14', 80, 'tcp', '', true)`); err != nil {
		t.Fatal(err)
	}
	snap, err := LoadSnapshot(ctx, tx, genRun)
	if err != nil || snap.RunID != genRun || len(snap.Annotations) != 1 {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	b, err := snap.Dojo()
	if err != nil {
		t.Fatal(err)
	}
	fs, err := dojo.NewCodec().Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.UniqueIDFromTool == "asi:sig:10.20.0.14:80:phpmyadmin" {
			t.Error("false positive exported")
		}
	}
	if err := store.DojoRecordPush(ctx, tx, store.DojoPush{RunID: &run.ID, Endpoint: "reimport-scan", Findings: len(fs), OK: true}); err != nil {
		t.Fatal(err)
	}
	if p, err := store.DojoRecentPushes(ctx, tx, 5); err != nil || len(p) == 0 {
		t.Fatalf("pushes %v %v", p, err)
	}
}

func importFile(ctx context.Context, t *testing.T, tx pgx.Tx, path string) int64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, obs, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	id, err := Store(ctx, tx, obs, &rep)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
