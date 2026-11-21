// Package diff compares scan runs and tracks host stability. Owned by W1-4.
package diff

import "github.com/chrobson/hacknation-agh/internal/model"

// Config defines host lifecycle thresholds (see config.UnstableConfig).
type Config struct {
	InactiveAfterMisses int
	UnstableIfFlips     int
	Window              int
}

// Compare is a pure function: given the previous and current run's services
// and the hosts' state history, it returns the changes of the current run.
// Keys are compared by model.AssetKey; product/version/banner/CPE changes
// produce ChangeChanged with Field/Old/New set.
type Compare func(prev, curr []model.ServiceObs, hist []model.HostState, cfg Config) []model.Change
