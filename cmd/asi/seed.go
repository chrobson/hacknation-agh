package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/target"
)

// Demo scan configuration created by `asi seed-demo`: auto port profile
// (all TCP ports for small targets), 1000 packets/s, 4 workers, manual.
const (
	demoConfigName = "Demo"
	demoMaxRate    = 1000
	demoWorkers    = 4
	demoTopPorts   = 1000
)

// seedTargets returns the targets `asi seed-demo` adds when none are given:
// host.docker.internal when the app reaches its host through the docker
// gateway (compose.hostgw.yml sets ASI_ALLOW_HOSTS), localhost otherwise
// (host network or native mode).
func seedTargets(cfg config.Config, args []string) []string {
	if len(args) > 0 {
		return args
	}
	if slices.Contains(cfg.AllowHosts, "host.docker.internal") {
		return []string{"host.docker.internal"}
	}
	return []string{"localhost"}
}

type seedResult struct {
	Targets  []string `json:"targets"`
	Imported int      `json:"imported"`
	ConfigID int64    `json:"config_id"`
	Config   string   `json:"config"`
	MaxRate  int      `json:"max_rate"`
	Profile  string   `json:"port_profile"`
}

// seedDemo adds the targets (allowlist-checked like any import) and creates
// or updates the demo scan configuration covering exactly these targets.
// It is idempotent.
func seedDemo(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, values []string) (seedResult, error) {
	res := seedResult{Targets: values, Config: demoConfigName, MaxRate: min(demoMaxRate, maxRate(cfg)), Profile: "auto"}
	entries := make([]target.Entry, len(values))
	for i, v := range values {
		entries[i] = target.Entry{Line: i + 1, Value: v, Tags: []string{"demo"}}
	}
	ts, rep := target.Importer{Allow: target.NewAllowlist(cfg.AllowedCIDRs)}.Prepare(ctx, entries)
	if len(rep.Errors) > 0 {
		var msgs []string
		for _, e := range rep.Errors {
			msgs = append(msgs, fmt.Sprintf("%s: %s", e.Value, e.Error))
		}
		return res, fmt.Errorf("targets rejected (ASI_ALLOWED_CIDRS / ASI_ALLOW_HOSTS): %s", strings.Join(msgs, "; "))
	}
	if len(ts) == 0 {
		return res, errors.New("no targets")
	}
	n, err := target.PGStore{DB: pool}.Insert(ctx, ts, nil)
	if err != nil {
		return res, err
	}
	res.Imported = n
	ids := make([]int64, 0, len(ts))
	for _, t := range ts {
		var id int64
		if err := pool.QueryRow(ctx, `SELECT id FROM targets WHERE value=$1`, t.Value).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return res, fmt.Errorf("target %q not stored", t.Value)
			}
			return res, err
		}
		ids = append(ids, id)
	}
	err = pool.QueryRow(ctx, `INSERT INTO scan_configs (name, target_ids, top_ports, max_rate, workers, port_profile, enabled)
		VALUES ($1, $2, $3, $4, $5, 'auto', true)
		ON CONFLICT (name) DO UPDATE SET target_ids=EXCLUDED.target_ids, max_rate=EXCLUDED.max_rate,
			workers=EXCLUDED.workers, port_profile='auto', enabled=true
		RETURNING id`, demoConfigName, ids, demoTopPorts, res.MaxRate, demoWorkers).Scan(&res.ConfigID)
	return res, err
}

func maxRate(cfg config.Config) int {
	if cfg.MaxRate > 0 {
		return cfg.MaxRate
	}
	return config.DefaultMaxRate
}
