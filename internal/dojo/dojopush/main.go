// Command dojopush is a development helper for `make e2e-dojo`: it validates
// a Generic Findings file offline, then sends it to a local DefectDojo with
// import-scan followed by reimport-scan (close_old_findings=true). The
// second call must not create duplicates. It is not part of the asi binary.
//
//	DOJO_URL=http://localhost:8081 DOJO_USER=admin DOJO_PASSWORD=... \
//	  go run ./internal/dojo/dojopush -file findings.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dojopush:", err)
		os.Exit(1)
	}
}

func run() error {
	file := flag.String("file", "", "Generic Findings JSON file")
	fromDB := flag.Bool("from-db", false, "generate the file from the latest run in ASI_DATABASE_URL instead of -file")
	out := flag.String("out", "", "with -from-db: also write the generated file here")
	product := flag.String("product", "Attack Surface Intelligence", "DefectDojo product name")
	engagement := flag.String("engagement", "e2e", "DefectDojo engagement name")
	validateOnly := flag.Bool("validate", false, "only validate the file offline")
	flag.Parse()
	var (
		b   []byte
		err error
	)
	switch {
	case *fromDB:
		if b, err = generate(os.Getenv("ASI_DATABASE_URL")); err != nil {
			return err
		}
		if *out != "" {
			if err := os.WriteFile(*out, b, 0o600); err != nil {
				return err
			}
		}
	case *file != "":
		if b, err = os.ReadFile(*file); err != nil {
			return err
		}
	default:
		return fmt.Errorf("-file or -from-db is required")
	}
	if err := dojo.Validate(b); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	fmt.Println("validate: OK")
	if *validateOnly {
		return nil
	}
	c := &dojo.Client{
		BaseURL:  envOr("DOJO_URL", "http://localhost:8081"),
		Token:    os.Getenv("DOJO_TOKEN"),
		Username: envOr("DOJO_USER", "admin"),
		Password: os.Getenv("DOJO_PASSWORD"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := c.Authenticate(ctx); err != nil {
		return err
	}
	p := dojo.PushParams{Product: *product, Engagement: *engagement, ScanDate: time.Now()}
	r1, err := c.ImportScan(ctx, p, b)
	if err != nil {
		return err
	}
	report("import-scan", r1)
	p.TestID = r1.ID()
	r2, err := c.ReimportScan(ctx, p, b)
	if err != nil {
		return err
	}
	report("reimport-scan", r2)
	return nil
}

// generate builds the Generic Findings file of the latest finished run.
func generate(dbURL string) ([]byte, error) {
	if dbURL == "" {
		return nil, fmt.Errorf("-from-db needs ASI_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	run, err := store.ExportLatestRun(ctx, pool)
	if err != nil {
		return nil, err
	}
	svcs, err := store.ExportServices(ctx, pool, run.ID)
	if err != nil {
		return nil, err
	}
	anns, err := store.ExportAnnotations(ctx, pool)
	if err != nil {
		return nil, err
	}
	fmt.Printf("generate: run #%d, %d services\n", run.ID, len(svcs))
	return dojo.NewCodec().Marshal(dojo.BuildFindings(run.Date(), svcs, anns))
}

func report(step string, r dojo.ImportResult) {
	stats := "{}"
	if len(r.Statistics) > 0 {
		var v any
		if json.Unmarshal(r.Statistics, &v) == nil {
			if b, err := json.Marshal(v); err == nil {
				stats = string(b)
			}
		}
	}
	fmt.Printf("%s: OK test=%d engagement=%d product=%d statistics=%s\n", step, r.ID(), r.EngagementID, r.ProductID, stats)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
