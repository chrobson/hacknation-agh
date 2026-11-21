package diff

import (
	"cmp"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// History window: the last N finished scan runs (?runs=, clamped).
const (
	DefaultHistoryRuns = 30
	MinHistoryRuns     = 5
	MaxHistoryRuns     = 100
)

// historyRuns reads ?runs=, defaulting to DefaultHistoryRuns and clamping
// to [MinHistoryRuns, MaxHistoryRuns].
func historyRuns(v url.Values) int {
	n, err := strconv.Atoi(v.Get("runs"))
	if err != nil {
		return DefaultHistoryRuns
	}
	return min(max(n, MinHistoryRuns), MaxHistoryRuns)
}

// Samples converts presence rows to Analyze input.
func Samples(ps []store.Presence) []Sample {
	out := make([]Sample, len(ps))
	for i, p := range ps {
		out[i] = Sample{At: p.StartedAt, Seen: p.Seen}
	}
	return out
}

// AvailabilityRow is one asset on the availability page.
type AvailabilityRow struct {
	Key model.AssetKey
	Availability
}

type availabilityData struct {
	Tab    string // hosts | services
	All    bool
	Runs   int
	Rows   []AvailabilityRow
	Hidden int // assets at 100% not listed
}

// AvailabilityRows analyses each asset and, unless all is set, keeps only
// assets seen in fewer than all of their covering runs. Rows are sorted by
// availability ascending, then by key.
func AvailabilityRows(ps []store.AssetPresence, loc *time.Location, all bool) (rows []AvailabilityRow, hidden int) {
	for _, p := range ps {
		a := Analyze(Samples(p.Samples), loc, DefaultMinPerBand)
		if !all && (a.Total == 0 || a.Seen == a.Total) {
			hidden++
			continue
		}
		rows = append(rows, AvailabilityRow{Key: p.Key, Availability: a})
	}
	slices.SortStableFunc(rows, func(a, b AvailabilityRow) int {
		return cmp.Or(cmp.Compare(a.Percent, b.Percent), CompareKeys(a.Key, b.Key))
	})
	return rows, hidden
}

func (h *handler) availability(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := availabilityData{Tab: "hosts", All: q.Get("all") == "1", Runs: historyRuns(q)}
	var ps []store.AssetPresence
	var err error
	if q.Get("tab") == "services" {
		d.Tab = "services"
		ps, err = store.ServicePresence(r.Context(), h.d.DB, d.Runs)
	} else {
		ps, err = store.HostPresence(r.Context(), h.d.DB, d.Runs)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	d.Rows, d.Hidden = AvailabilityRows(ps, time.Local, d.All)
	h.render(w, "availability.html", "base", http.StatusOK, d)
}

type assetData struct {
	Key   model.AssetKey
	Runs  int
	Hist  store.AssetTimeline
	Avail Availability
}

func (h *handler) asset(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	k, err := ParseKey(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d := assetData{Key: k, Runs: historyRuns(q)}
	if d.Hist, err = store.AssetHistory(r.Context(), h.d.DB, k, d.Runs); err != nil {
		h.fail(w, err)
		return
	}
	d.Avail = Analyze(CoveredSamples(d.Hist.Runs), time.Local, DefaultMinPerBand)
	h.render(w, "asset.html", "base", http.StatusOK, d)
}

// CoveredSamples keeps the runs that covered the asset.
func CoveredSamples(runs []store.AssetRun) []Sample {
	var out []Sample
	for _, r := range runs {
		if r.Covered {
			out = append(out, Sample{At: r.StartedAt, Seen: r.Seen})
		}
	}
	return out
}
