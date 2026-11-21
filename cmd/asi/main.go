// Command asi is the single binary of Attack Surface Intelligence:
//
//	asi migrate                       apply database migrations
//	asi serve                         web UI + API + scheduler
//	asi scan [config]                 run one scan now (config id or name; default: all targets)
//	asi verify <file> [-run N]        compare a run with an expected lab file (precision/recall)
//	asi import <file>                 import targets (CSV/JSON), nmap XML or Generic Findings JSON
//	asi export dojo|csv|json [run]    export results to stdout
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/app"
	"github.com/chrobson/hacknation-agh/internal/auth"
	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/db"
	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/export"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/target"
	"github.com/chrobson/hacknation-agh/internal/web"
)

const usage = `usage: asi <command>
  migrate                       apply database migrations
  serve                         web UI, API and scan scheduler
  scan [config]                 run a scan now (config id or name; default: all targets)
  verify <expected.json> [-run N] [-min 0.9]
                                precision/recall of a run against a lab expectation
  import <file>                 targets CSV/JSON, nmap XML or Generic Findings JSON
  export dojo|csv|json [run]    export a run (default: latest) to stdout
  validate-dojo <file>          validate a Generic Findings JSON file offline`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "asi:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(os.Stderr, usage)
		if len(args) == 0 {
			return errors.New("missing command")
		}
		return nil
	}
	if args[0] == "validate-dojo" {
		if len(args) != 2 {
			return errors.New("usage: asi validate-dojo <file>")
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		if err := dojo.Validate(b); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "migrate", "serve", "scan", "verify", "import", "export":
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	deps := web.Deps{DB: pool, Config: cfg, Log: log}

	switch args[0] {
	case "migrate":
		applied, err := db.Migrate(ctx, pool)
		log.Info("migrations applied", "versions", applied)
		return err
	case "serve":
		return serve(ctx, deps)
	case "scan":
		return scanCmd(ctx, deps, args[1:])
	case "verify":
		return verifyCmd(ctx, pool, args[1:])
	case "import":
		return importCmd(ctx, deps, args[1:])
	case "export":
		return exportCmd(ctx, pool, args[1:])
	}
	return nil
}

func serve(ctx context.Context, d web.Deps) error {
	if applied, err := db.Migrate(ctx, d.DB); err != nil {
		return err
	} else if len(applied) > 0 {
		d.Log.Info("migrations applied", "versions", applied)
	}
	if err := auth.Seed(ctx, d.DB, d.Config); err != nil {
		return fmt.Errorf("seed users: %w", err)
	}
	// A fresh database gets one manual configuration covering every target,
	// so "Skanuj teraz" works right after adding targets.
	if _, err := d.DB.Exec(ctx, `INSERT INTO scan_configs (name, target_ids)
		SELECT $1, '{}' WHERE NOT EXISTS (SELECT 1 FROM scan_configs)`, DefaultConfigName); err != nil {
		return fmt.Errorf("default scan configuration: %w", err)
	}
	core, err := app.NewCore(ctx, d)
	if err != nil {
		return err
	}
	h, err := app.Router(ctx, core)
	if err != nil {
		return err
	}
	tick := d.Config.TickEvery
	if tick <= 0 {
		tick = time.Minute
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		if err := core.Runner.Loop(ctx, tick); err != nil && ctx.Err() == nil {
			d.Log.Error("scheduler stopped", "err", err)
		}
	}()
	d.Log.Info("listening", "addr", d.Config.HTTPAddr, "allowed", d.Config.AllowedCIDRs, "exclude", d.Config.ScanExclude)
	err = app.Serve(ctx, d.Config.HTTPAddr, h)
	// Active runs persist as paused and resume in the next window.
	<-loopDone
	core.Runner.Wait()
	return err
}

func scanCmd(ctx context.Context, d web.Deps, args []string) error {
	core, err := app.NewCore(ctx, d)
	if err != nil {
		return err
	}
	if err := core.Runner.Recover(ctx); err != nil {
		return err
	}
	cfgID, err := resolveConfig(ctx, d.DB, args)
	if err != nil {
		return err
	}
	st := store.NewScanStore(d.DB)
	done := make(chan struct{})
	t0 := time.Now()
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				for _, id := range core.Runner.ActiveRuns() {
					if c, err := st.CountChunks(ctx, id); err == nil {
						d.Log.Info("scan progress", "run", id, "done", c.Done, "failed", c.Failed,
							"running", c.Running, "pending", c.Pending, "elapsed", time.Since(t0).Round(time.Second).String())
					}
				}
			}
		}
	}()
	runID, err := core.Runner.RunConfig(ctx, cfgID)
	close(done)
	if err != nil {
		return fmt.Errorf("run %d: %w", runID, err)
	}
	r, err := app.GetRun(context.WithoutCancel(ctx), d.DB, runID)
	if err != nil {
		return err
	}
	out, _ := json.Marshal(map[string]any{"run_id": runID, "status": r.Status, "duration": r.Duration(),
		"chunks": r.ChunksTotal, "chunks_failed": r.ChunksFail, "hosts_up": r.HostsUp, "services": r.Services})
	fmt.Println(string(out))
	return nil
}

// DefaultConfigName is the configuration `asi scan` uses without arguments.
const DefaultConfigName = "Wszystkie cele"

func resolveConfig(ctx context.Context, pool *pgxpool.Pool, args []string) (int64, error) {
	if len(args) > 0 {
		if id, err := strconv.ParseInt(args[0], 10, 64); err == nil {
			return id, nil
		}
		var id int64
		err := pool.QueryRow(ctx, `SELECT id FROM scan_configs WHERE name=$1`, args[0]).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("no scan configuration named %q", args[0])
		}
		return id, err
	}
	var id int64
	err := pool.QueryRow(ctx, `INSERT INTO scan_configs (name, target_ids) VALUES ($1, '{}')
		ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id`, DefaultConfigName).Scan(&id)
	return id, err
}

func verifyCmd(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	runID := fs.Int64("run", 0, "run id (default: latest done run)")
	minScore := fs.Float64("min", 0.9, "minimum precision/recall for pass")
	var file string
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		file, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if file == "" {
		file = fs.Arg(0)
	}
	if file == "" {
		return errors.New("usage: asi verify <lab/expected/runN.json> [-run N] [-min 0.9]")
	}
	e, err := app.LoadExpected(file)
	if err != nil {
		return err
	}
	rep, err := app.Verify(ctx, pool, e, file, *runID, *minScore)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return err
	}
	if !rep.Pass {
		return fmt.Errorf("verify failed: %v", rep.Failures)
	}
	return nil
}

func importCmd(ctx context.Context, d web.Deps, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: asi import <file>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if export.DetectFormat(b) != export.FormatUnknown {
		export.AllowHost = target.NewAllowlist(d.Config.AllowedCIDRs).AllowsAddr
		rep, err := export.Import(ctx, d.DB, b)
		if err != nil {
			return err
		}
		p := &app.Pipeline{Pool: d.DB, Unstable: d.Config.Unstable, Log: d.Log}
		if err := p.ApplyDiff(ctx, rep.RunID); err != nil {
			return err
		}
		return enc.Encode(rep)
	}
	entries, err := target.ParseInput(target.DetectFormat(filepath.Base(args[0]), b), b)
	if err != nil {
		return err
	}
	ts, rep := target.Importer{Allow: target.NewAllowlist(d.Config.AllowedCIDRs)}.Prepare(ctx, entries)
	n, err := target.PGStore{DB: d.DB}.Insert(ctx, ts, nil)
	if err != nil {
		return err
	}
	rep.Finish(len(ts), n)
	return enc.Encode(rep)
}

func exportCmd(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: asi export dojo|csv|json [run]")
	}
	var runID int64
	if len(args) == 2 {
		v := args[1]
		if len(v) > 5 && v[:5] == "-run=" {
			v = v[5:]
		}
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("run: %w", err)
		}
		runID = id
	}
	s, err := export.LoadSnapshot(ctx, pool, runID)
	if err != nil {
		return err
	}
	switch args[0] {
	case "dojo":
		b, err := s.Dojo()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	case "csv":
		return export.WriteCSV(os.Stdout, s)
	case "json":
		return export.WriteJSON(os.Stdout, s)
	}
	return fmt.Errorf("unknown export format %q (dojo|csv|json)", args[0])
}
