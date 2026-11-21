//go:build integration

package store_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/sig"
	"github.com/chrobson/hacknation-agh/internal/store"
)

func TestFPStoreIntegration(t *testing.T) {
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
	defer tx.Rollback(ctx) // leave the database untouched

	var runID, svcID int64
	if err := tx.QueryRow(ctx, `INSERT INTO scan_runs (status) VALUES ('done') RETURNING id`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO services (run_id, ip, port, proto) VALUES ($1, '10.20.1.5', 443, 'tcp') RETURNING id`, runID).Scan(&svcID); err != nil {
		t.Fatal(err)
	}

	fav := int32(-1234)
	obs := model.HTTPObs{
		ServiceID: svcID, URL: "https://10.20.1.5/", Status: 200, Title: "Panel",
		Headers:     map[string][]string{"Server": {"nginx"}},
		Cookies:     []model.Cookie{{Name: "sid", Secure: true}},
		Redirects:   []model.Redirect{{URL: "http://10.20.1.5/", Status: 301}},
		TLS:         &model.TLSInfo{Subject: "CN=x", SelfSigned: true, NotAfter: time.Unix(1700000000, 0).UTC(), SANs: []string{}},
		FaviconMMH3: &fav, BodySHA256: "ab", Body: []byte("never stored"),
	}
	if err := store.SaveHTTPObs(ctx, tx, obs); err != nil {
		t.Fatal(err)
	}
	obs.Title = "Panel 2"
	if err := store.SaveHTTPObs(ctx, tx, obs); err != nil { // upsert
		t.Fatal(err)
	}
	got, err := store.GetHTTPObs(ctx, tx, svcID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Panel 2" || got.Body != nil || *got.FaviconMMH3 != fav || !got.TLS.SelfSigned ||
		got.Cookies[0].Name != "sid" || got.Redirects[0].Status != 301 || got.Headers["Server"][0] != "nginx" {
		t.Fatalf("got %+v", got)
	}

	ds := []model.Detection{{SignatureID: "nginx", Name: "nginx", Category: "server", Confidence: 85, Evidence: map[string]string{"version": "1.25"}}}
	if err := store.ReplaceDetections(ctx, tx, svcID, ds); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceDetections(ctx, tx, svcID, ds); err != nil {
		t.Fatal(err)
	}
	list, err := store.ListDetections(ctx, tx, svcID)
	if err != nil || len(list) != 1 || list[0].Evidence["version"] != "1.25" {
		t.Fatalf("detections %+v %v", list, err)
	}

	if err := store.SaveLegacyTLS(ctx, tx, svcID, httpfp.LegacyTLS{TLS10: true, TLS10Cipher: "TLS_RSA_WITH_AES_128_CBC_SHA"}); err != nil {
		t.Fatal(err)
	}
	lt, err := store.GetLegacyTLS(ctx, tx, svcID)
	if err != nil || !lt.TLS10 || lt.TLS11 {
		t.Fatalf("legacy %+v %v", lt, err)
	}

	// Signatures: builtin sync, custom CRUD, builtin protection.
	if err := sig.SyncBuiltin(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSignatureEnabled(ctx, tx, "nginx", false); err != nil {
		t.Fatal(err)
	}
	if err := sig.SyncBuiltin(ctx, tx); err != nil { // must keep enabled=false
		t.Fatal(err)
	}
	if r, _ := store.GetSignature(ctx, tx, "nginx"); r.Enabled || !r.Builtin {
		t.Fatalf("nginx row %+v", r)
	}
	custom, err := sig.Parse([]byte("id: zz-custom\nname: C\ncategory: other\nconfidence: 5\nmatchers:\n  - {type: title, regex: x}\n"))
	if err != nil {
		t.Fatal(err)
	}
	dbs := sig.NewDBStore(tx)
	if err := dbs.Create(ctx, custom); err != nil {
		t.Fatal(err)
	}
	if err := dbs.Create(ctx, custom); err == nil {
		t.Fatal("duplicate create accepted")
	}
	if err := dbs.Update(ctx, "nginx", &sig.Signature{ID: "nginx", Raw: "x"}); !errors.Is(err, store.ErrSignatureBuiltin) {
		t.Fatalf("update builtin: %v", err)
	}
	if err := dbs.Delete(ctx, "wordpress"); !errors.Is(err, store.ErrSignatureBuiltin) {
		t.Fatalf("delete builtin: %v", err)
	}
	enabled, err := sig.LoadEnabled(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, s := range enabled {
		ids = append(ids, s.ID)
	}
	joined := strings.Join(ids, ",")
	if strings.Contains(joined, "nginx") || !strings.Contains(joined, "zz-custom") || !strings.Contains(joined, "wordpress") {
		t.Fatalf("enabled = %s", joined)
	}
	if err := dbs.Delete(ctx, "zz-custom"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSignature(ctx, tx, "zz-custom"); !errors.Is(err, store.ErrSignatureNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
