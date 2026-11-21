package diff

import (
	"strconv"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// ServiceInstability returns an unstable event for every service that
// appeared or disappeared in this run (a new or gone change in cs) and has,
// counting this run, at least cfg.UnstableIfFlips such transitions among the
// last cfg.Window runs (the same window as host instability: Window
// observations hold Window-1 transitions). prior holds, per service key, the
// number of new/gone changes recorded in the previous PriorRuns(cfg) runs
// (see store.DiffServiceFlips).
//
// A service on a host reported unstable in cs is skipped: the host-level
// event already explains why its services come and go.
func ServiceInstability(cs []model.Change, prior map[model.AssetKey]int, cfg Config) []model.Change {
	if cfg.UnstableIfFlips <= 0 {
		return nil
	}
	hostUnstable := map[model.AssetKey]bool{}
	for _, c := range cs {
		if c.Kind == model.ChangeUnstable && c.Key.Port == 0 {
			hostUnstable[model.AssetKey{IP: c.Key.IP.Unmap()}] = true
		}
	}
	var out []model.Change
	seen := map[model.AssetKey]bool{}
	for _, c := range cs {
		if c.Kind != model.ChangeNew && c.Kind != model.ChangeGone {
			continue
		}
		k := normKey(c.Key)
		if seen[k] || hostUnstable[model.AssetKey{IP: k.IP}] {
			continue
		}
		seen[k] = true
		if n := prior[k] + 1; n >= cfg.UnstableIfFlips {
			out = append(out, model.Change{Kind: model.ChangeUnstable, Key: k, Field: "flips", New: strconv.Itoa(n)})
		}
	}
	return out
}

// PriorRuns is the number of earlier runs whose service transitions count
// towards instability. A window of cfg.Window observations holds Window-1
// transitions; the current run's change is one of them.
func PriorRuns(cfg Config) int { return keepFlips(cfg) - 2 }
