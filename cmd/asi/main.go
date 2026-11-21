// Command asi is the single binary of Attack Surface Intelligence:
//
//	asi migrate          apply database migrations
//	asi serve            web UI + API + scheduler
//	asi scan [config]    run one scan now
//	asi verify <file>    compare the latest run with an expected lab file
//	asi import <file>    import targets (CSV/JSON), nmap XML or Generic Findings JSON
//	asi export <fmt>     export results: dojo | csv | json
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/db"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "asi:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: asi <migrate|serve|scan|verify|import|export>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "migrate":
		pool, err := db.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer pool.Close()
		applied, err := db.Migrate(ctx, pool)
		log.Info("migrations applied", "versions", applied)
		return err
	case "serve", "scan", "verify", "import", "export":
		return fmt.Errorf("%s: not implemented yet", args[0])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
