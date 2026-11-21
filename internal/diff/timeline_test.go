package diff

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

func runPoint(id int64, counts map[model.ChangeKind]int) store.RunPoint {
	return store.RunPoint{RunID: id, StartedAt: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), HostsUp: int(id), Services: 2 * int(id), Counts: counts}
}

func barHeight(b Bar) float64 {
	var h float64
	for _, s := range b.Segments {
		h += s.H
	}
	return h
}

func TestBuildChartProportional(t *testing.T) {
	c := BuildChart([]store.RunPoint{
		runPoint(1, map[model.ChangeKind]int{model.ChangeNew: 10}),
		runPoint(2, map[model.ChangeKind]int{model.ChangeNew: 2, model.ChangeGone: 3}),
	})
	if len(c.Bars) != 2 || !c.Enough() || c.MaxChanges != 10 {
		t.Fatalf("chart %+v", c)
	}
	full := chartBottom - chartTop
	if h := barHeight(c.Bars[0]); math.Abs(h-full) > 1e-9 {
		t.Errorf("max bar height %v want %v", h, full)
	}
	if h := barHeight(c.Bars[1]); math.Abs(h-full/2) > 1e-9 {
		t.Errorf("half bar height %v want %v", h, full/2)
	}
	// Segments stack upward from the baseline in KindOrder (new before gone).
	segs := c.Bars[1].Segments
	if len(segs) != 2 || segs[0].Kind != model.ChangeNew || segs[1].Kind != model.ChangeGone ||
		math.Abs(segs[0].Y+segs[0].H-chartBottom) > 1e-9 || math.Abs(segs[1].Y+segs[1].H-segs[0].Y) > 1e-9 {
		t.Errorf("segments %+v", segs)
	}
	if !strings.Contains(c.Bars[1].Title, "przebieg #2") || !strings.Contains(c.Bars[1].Title, "zniknięte 3") {
		t.Errorf("title %q", c.Bars[1].Title)
	}
	if strings.Count(c.HostsLine, ",") != 2 || strings.Count(c.ServicesLine, ",") != 2 {
		t.Errorf("lines %q %q", c.HostsLine, c.ServicesLine)
	}
}

func TestBuildChartEmpty(t *testing.T) {
	c := BuildChart(nil)
	if len(c.Bars) != 0 || c.Enough() || c.HostsLine != "" {
		t.Errorf("empty chart %+v", c)
	}
	if BuildChart([]store.RunPoint{runPoint(1, nil)}).Enough() {
		t.Errorf("one run is not enough")
	}
}

func TestBuildChartKeepsNewest(t *testing.T) {
	var ps []store.RunPoint
	for i := int64(1); i <= 45; i++ {
		ps = append(ps, runPoint(i, map[model.ChangeKind]int{model.ChangeChanged: 1}))
	}
	c := BuildChart(ps)
	if len(c.Bars) != ChartRuns || c.Bars[0].RunID != 16 || c.Bars[ChartRuns-1].RunID != 45 {
		t.Fatalf("bars %d first %d last %d", len(c.Bars), c.Bars[0].RunID, c.Bars[len(c.Bars)-1].RunID)
	}
	last := c.Bars[ChartRuns-1]
	if last.SlotX+last.SlotW > chartRight+1e-9 || c.Bars[0].SlotX < chartLeft {
		t.Errorf("bars outside plot: %+v", last)
	}
}

func TestBuildChartZeroChangeSlot(t *testing.T) {
	c := BuildChart([]store.RunPoint{
		runPoint(1, map[model.ChangeKind]int{model.ChangeNew: 4}),
		runPoint(2, map[model.ChangeKind]int{}),
	})
	b := c.Bars[1]
	if len(b.Segments) != 0 || b.SlotW <= 0 || b.Total != 0 || !strings.Contains(b.Title, "brak zmian") {
		t.Errorf("zero-change bar %+v", b)
	}
	// All zero: no division by zero.
	c = BuildChart([]store.RunPoint{runPoint(1, nil), runPoint(2, nil)})
	if len(c.Bars) != 2 || c.MaxChanges != 0 {
		t.Errorf("all-zero chart %+v", c)
	}
}
