package diff

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// ErrAlreadyApplied is returned by ApplyRun when the run was applied before.
var ErrAlreadyApplied = errors.New("diff already applied for this run")

// Result describes what ApplyRun did.
type Result struct {
	RunID     int64
	PrevRunID int64 // 0 = baseline run, no changes recorded
	Changes   []model.Change
	Hosts     []model.HostState // states of the hosts in the run's scope after the run
}

// ApplyRun compares run runID with the previous finished scan run (imports
// are never a baseline; an import is compared only on the hosts it contains), persists the
// changes and advances host_state, all in one transaction. Call it once the
// run's host_obs and services are stored (typically when the run is marked
// done). The first run ever is a baseline: host states are created but no
// changes are recorded. Applying the same run twice returns ErrAlreadyApplied.
func ApplyRun(ctx context.Context, pool *pgxpool.Pool, runID int64, cfg Config, now time.Time) (Result, error) {
	var res Result
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		res, err = ApplyRunTx(ctx, tx, runID, cfg, now)
		return err
	})
	return res, err
}

// DropUncarried removes "changed" rows whose new value is empty. An import
// file (nmap XML, Generic Findings) carries only some fields; a field missing
// from the file is unknown, not removed.
func DropUncarried(cs []model.Change) []model.Change {
	out := cs[:0]
	for _, c := range cs {
		if c.Kind == model.ChangeChanged && c.New == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ApplyRunTx is ApplyRun inside a caller-provided transaction.
func ApplyRunTx(ctx context.Context, tx pgx.Tx, runID int64, cfg Config, now time.Time) (Result, error) {
	res := Result{RunID: runID}
	if err := store.DiffLockRuns(ctx, tx); err != nil {
		return res, err
	}
	applied, err := store.DiffRunApplied(ctx, tx, runID)
	if err != nil {
		return res, err
	}
	if applied {
		return res, ErrAlreadyApplied
	}
	if res.PrevRunID, err = store.DiffPrevRunID(ctx, tx, runID); err != nil {
		return res, fmt.Errorf("previous run: %w", err)
	}
	curr, err := store.DiffRunServices(ctx, tx, runID)
	if err != nil {
		return res, fmt.Errorf("current services: %w", err)
	}
	var prev []model.ServiceObs
	if res.PrevRunID != 0 {
		if prev, err = store.DiffRunServicesInScope(ctx, tx, res.PrevRunID, runID); err != nil {
			return res, fmt.Errorf("previous services: %w", err)
		}
	}
	obs, err := store.DiffRunHostObs(ctx, tx, runID)
	if err != nil {
		return res, fmt.Errorf("host observations: %w", err)
	}
	known, err := store.DiffHostStatesInScope(ctx, tx, runID)
	if err != nil {
		return res, fmt.Errorf("host states: %w", err)
	}

	isImport, err := store.DiffRunIsImport(ctx, tx, runID)
	if err != nil {
		return res, err
	}

	res.Hosts = Advance(known, obs, curr, runID, now, cfg)
	if res.PrevRunID != 0 {
		res.Changes = Diff(prev, curr, res.Hosts, cfg)
		if isImport {
			res.Changes = DropUncarried(res.Changes)
		} else {
			// Imports carry no HTTP timing; scans compare response times.
			lat, err := runLatencies(ctx, tx, runID, res.PrevRunID)
			if err != nil {
				return res, fmt.Errorf("response times: %w", err)
			}
			if lc := LatencyChanges(prev, curr, lat); len(lc) > 0 {
				res.Changes = append(res.Changes, lc...)
				SortChanges(res.Changes)
			}
		}
		for i := range res.Changes {
			res.Changes[i].RunID = runID
			res.Changes[i].PrevRunID = res.PrevRunID
		}
	}

	if err := store.SaveHostStates(ctx, tx, res.Hosts); err != nil {
		return res, err
	}
	if err := store.InsertChanges(ctx, tx, res.Changes); err != nil {
		return res, fmt.Errorf("insert changes: %w", err)
	}
	if err := store.DiffMarkApplied(ctx, tx, runID, res.PrevRunID, len(res.Changes)); err != nil {
		return res, err
	}
	return res, nil
}
