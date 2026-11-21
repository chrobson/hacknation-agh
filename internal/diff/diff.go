// Package diff compares scan runs and tracks host stability. Owned by W1-4.
package diff

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/model"
)

// Config defines host lifecycle thresholds (see config.UnstableConfig).
type Config struct {
	InactiveAfterMisses int
	UnstableIfFlips     int
	Window              int
}

// FromConfig converts the process configuration into diff thresholds.
func FromConfig(u config.UnstableConfig) Config {
	return Config{
		InactiveAfterMisses: u.InactiveAfterMisses,
		UnstableIfFlips:     u.UnstableIfFlips,
		Window:              u.Window,
	}
}

// Compare is a pure function: given the previous and current run's services
// and the hosts' state history, it returns the changes of the current run.
// Keys are compared by model.AssetKey; product/version/banner/CPE changes
// produce ChangeChanged with Field/Old/New set.
type Compare func(prev, curr []model.ServiceObs, hist []model.HostState, cfg Config) []model.Change

// Ensure Diff satisfies the frozen contract.
var _ Compare = Diff

// Diff is the reference implementation of Compare.
//
// hist holds the host states AFTER the current run has been applied with
// Step, i.e. the last entry of each host's Flips is its observation in the
// current run. Hosts whose last flip belongs to an older run were not in the
// current run's scope and produce no host-level change.
//
// The current run ID is taken from curr (or, if curr is empty, the newest
// flip in hist); the previous run ID from prev (or the second newest flip).
// Output is sorted by (IP, port, proto, vhost) with host-level events first.
func Diff(prev, curr []model.ServiceObs, hist []model.HostState, cfg Config) []model.Change {
	runID, prevRunID := runIDs(prev, curr, hist)
	out := CompareServices(prev, curr)
	out = append(out, HostChanges(hist, runID, cfg)...)
	for i := range out {
		out[i].RunID = runID
		out[i].PrevRunID = prevRunID
	}
	SortChanges(out)
	return out
}

// Fields compared between two observations of the same service, in output order.
var comparedFields = []struct {
	name string
	get  func(model.ServiceObs) string
}{
	{"product", func(s model.ServiceObs) string { return s.Product }},
	{"version", func(s model.ServiceObs) string { return s.Version }},
	{"extrainfo", func(s model.ServiceObs) string { return s.ExtraInfo }},
	{"cpe", func(s model.ServiceObs) string { return s.CPE }},
	{"banner", func(s model.ServiceObs) string { return s.Banner }},
}

// CompareServices returns new/gone/changed service changes between two runs,
// keyed by model.AssetKey. A changed service yields one change per differing
// field. RunID/PrevRunID are left zero; output order is unspecified (see
// SortChanges).
func CompareServices(prev, curr []model.ServiceObs) []model.Change {
	pm := make(map[model.AssetKey]model.ServiceObs, len(prev))
	for _, s := range prev {
		pm[normKey(s.Key)] = s
	}
	cm := make(map[model.AssetKey]model.ServiceObs, len(curr))
	for _, s := range curr {
		cm[normKey(s.Key)] = s
	}
	var out []model.Change
	for k, c := range cm {
		p, ok := pm[k]
		if !ok {
			out = append(out, model.Change{Kind: model.ChangeNew, Key: k, New: summary(c)})
			continue
		}
		for _, f := range comparedFields {
			if o, n := f.get(p), f.get(c); o != n {
				out = append(out, model.Change{Kind: model.ChangeChanged, Key: k, Field: f.name, Old: o, New: n})
			}
		}
	}
	for k, p := range pm {
		if _, ok := cm[k]; !ok {
			out = append(out, model.Change{Kind: model.ChangeGone, Key: k, Old: summary(p)})
		}
	}
	return out
}

// HostChanges derives host_up/host_down/unstable events of run runID from
// host states that already include that run's observation.
func HostChanges(hist []model.HostState, runID int64, cfg Config) []model.Change {
	var out []model.Change
	for _, h := range hist {
		out = append(out, hostEvents(h, runID, cfg)...)
	}
	return out
}

func hostEvents(h model.HostState, runID int64, cfg Config) []model.Change {
	n := len(h.Flips)
	if n == 0 || h.Flips[n-1].RunID != runID {
		return nil
	}
	key := model.AssetKey{IP: h.IP.Unmap()}
	last := h.Flips[n-1]
	flipped := n == 1 && last.Up || n > 1 && h.Flips[n-2].Up != last.Up
	if !flipped {
		return nil
	}
	var out []model.Change
	if last.Up {
		out = append(out, model.Change{Kind: model.ChangeHostUp, Key: key, New: string(model.HostUp)})
	} else {
		out = append(out, model.Change{Kind: model.ChangeHostDown, Key: key, Old: string(model.HostUp), New: string(model.HostDown)})
	}
	// Report instability whenever an unstable host flips again, so analysts
	// see each flap of a host already marked unstable.
	if h.State == model.HostUnstable {
		out = append(out, model.Change{
			Kind: model.ChangeUnstable, Key: key,
			Field: "flips", New: strconv.Itoa(Transitions(windowOf(h.Flips, cfg))),
		})
	}
	return out
}

// Step advances one host's lifecycle with its observation in run runID.
// prev is nil for a host never seen before. now is used for FirstSeen and
// LastSeen. Applying the same run twice is a no-op.
//
// Rules (thresholds from cfg):
//   - up resets Misses; down increments it;
//   - inactive: not up and Misses >= InactiveAfterMisses;
//   - unstable: at least UnstableIfFlips up/down transitions among the last
//     Window observations (stored in Flips, which keeps Window entries);
//   - otherwise up or down per the observation.
func Step(prev *model.HostState, ip netip.Addr, up bool, runID int64, now time.Time, cfg Config) model.HostState {
	var h model.HostState
	if prev != nil {
		h = *prev
		h.Flips = slices.Clone(prev.Flips)
		if n := len(h.Flips); n > 0 && h.Flips[n-1].RunID == runID {
			return h
		}
	} else {
		h = model.HostState{IP: ip.Unmap(), FirstSeen: now, LastSeen: now}
	}
	h.Flips = append(h.Flips, model.Flip{RunID: runID, Up: up})
	if k := keepFlips(cfg); len(h.Flips) > k {
		h.Flips = slices.Clone(h.Flips[len(h.Flips)-k:])
	}
	if up {
		h.Misses = 0
		h.LastSeen = now
	} else {
		h.Misses++
	}
	h.State = Classify(h.Flips, h.Misses, cfg)
	return h
}

// Classify returns the lifecycle state for a flip history and miss count.
func Classify(flips []model.Flip, misses int, cfg Config) model.HostStateKind {
	if len(flips) == 0 {
		return model.HostDown
	}
	last := flips[len(flips)-1]
	if !last.Up && cfg.InactiveAfterMisses > 0 && misses >= cfg.InactiveAfterMisses {
		return model.HostInactive
	}
	if cfg.UnstableIfFlips > 0 && Transitions(windowOf(flips, cfg)) >= cfg.UnstableIfFlips {
		return model.HostUnstable
	}
	if last.Up {
		return model.HostUp
	}
	return model.HostDown
}

// Transitions counts up/down changes between consecutive observations.
func Transitions(flips []model.Flip) int {
	n := 0
	for i := 1; i < len(flips); i++ {
		if flips[i].Up != flips[i-1].Up {
			n++
		}
	}
	return n
}

func keepFlips(cfg Config) int { return max(cfg.Window, 2) }

func windowOf(flips []model.Flip, cfg Config) []model.Flip {
	if k := keepFlips(cfg); len(flips) > k {
		return flips[len(flips)-k:]
	}
	return flips
}

// SortChanges orders changes by asset key, host-level events first, then by
// kind and field, for stable output.
func SortChanges(cs []model.Change) {
	slices.SortStableFunc(cs, func(a, b model.Change) int {
		return cmp.Or(
			CompareKeys(a.Key, b.Key),
			cmp.Compare(kindOrder(a.Kind), kindOrder(b.Kind)),
			cmp.Compare(fieldOrder(a.Field), fieldOrder(b.Field)),
		)
	})
}

// CompareKeys orders asset keys by IP, port, proto, vhost.
func CompareKeys(a, b model.AssetKey) int {
	return cmp.Or(
		a.IP.Compare(b.IP),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.Proto, b.Proto),
		cmp.Compare(a.VHost, b.VHost),
	)
}

// KindOrder lists change kinds in display order.
var KindOrder = []model.ChangeKind{
	model.ChangeHostUp, model.ChangeHostDown, model.ChangeUnstable,
	model.ChangeNew, model.ChangeGone, model.ChangeChanged,
}

func kindOrder(k model.ChangeKind) int {
	if i := slices.Index(KindOrder, k); i >= 0 {
		return i
	}
	return len(KindOrder)
}

func fieldOrder(f string) int {
	for i, cf := range comparedFields {
		if cf.name == f {
			return i
		}
	}
	return len(comparedFields)
}

func normKey(k model.AssetKey) model.AssetKey {
	k.IP = k.IP.Unmap()
	return k
}

// summary is a short human description of a service for new/gone changes.
func summary(s model.ServiceObs) string {
	out := s.Product
	if s.Version != "" {
		if out != "" {
			out += " "
		}
		out += s.Version
	}
	return out
}

func runIDs(prev, curr []model.ServiceObs, hist []model.HostState) (runID, prevRunID int64) {
	for _, s := range curr {
		runID = max(runID, s.RunID)
	}
	if runID == 0 {
		for _, h := range hist {
			if n := len(h.Flips); n > 0 {
				runID = max(runID, h.Flips[n-1].RunID)
			}
		}
	}
	for _, s := range prev {
		prevRunID = max(prevRunID, s.RunID)
	}
	if prevRunID == 0 {
		for _, h := range hist {
			for _, f := range h.Flips {
				if f.RunID < runID {
					prevRunID = max(prevRunID, f.RunID)
				}
			}
		}
	}
	return runID, prevRunID
}

// Advance applies run runID to the hosts in scope and returns their next
// states, sorted by IP. known are the current states of hosts covered by the
// run; a known host absent from obs (and without services in curr) counts as
// a miss. A host is up if obs says so or it has a service in curr. Hosts seen
// for the first time are tracked only once they are up.
func Advance(known []model.HostState, obs []model.HostObs, curr []model.ServiceObs, runID int64, now time.Time, cfg Config) []model.HostState {
	up := make(map[netip.Addr]bool)
	for _, o := range obs {
		ip := o.IP.Unmap()
		up[ip] = up[ip] || o.Up
	}
	for _, s := range curr {
		up[s.Key.IP.Unmap()] = true
	}
	out := make([]model.HostState, 0, len(known)+len(up))
	seen := make(map[netip.Addr]bool, len(known))
	for i := range known {
		ip := known[i].IP.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, Step(&known[i], ip, up[ip], runID, now, cfg))
	}
	for ip, isUp := range up {
		if isUp && !seen[ip] {
			out = append(out, Step(nil, ip, true, runID, now, cfg))
		}
	}
	slices.SortFunc(out, func(a, b model.HostState) int { return a.IP.Compare(b.IP) })
	return out
}
