package diff

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// Chart geometry (SVG user units, viewBox 0 0 ChartWidth ChartHeight).
const (
	ChartWidth  = 720
	ChartHeight = 200
	ChartRuns   = 30 // at most this many runs, newest kept

	chartLeft   = 40.0
	chartRight  = 710.0
	chartTop    = 10.0
	chartBottom = 170.0 // baseline; run labels below it
)

// Segment is one kind's part of a run's stacked bar.
type Segment struct {
	Kind  model.ChangeKind
	Count int
	Y, H  float64
}

// Bar is one run: a clickable slot (full height, also for zero-change runs)
// with stacked segments in KindOrder.
type Bar struct {
	RunID        int64
	SlotX, SlotW float64
	X, W         float64
	LabelX       float64
	Total        int
	Title        string
	Segments     []Segment
}

// Chart holds the coordinates of the change timeline (inline SVG).
type Chart struct {
	Bars         []Bar
	HostsLine    string // polyline points for hosts up
	ServicesLine string // polyline points for services
	MaxChanges   int
	MaxAssets    int
	Top, Bottom  float64
}

// Enough reports whether there are at least two runs to compare.
func (c Chart) Enough() bool { return len(c.Bars) >= 2 }

// BuildChart lays out up to ChartRuns points (oldest first): one stacked bar
// per run scaled to the largest change total, and polylines for hosts up and
// services scaled to the largest of the two.
func BuildChart(points []store.RunPoint) Chart {
	if len(points) > ChartRuns {
		points = points[len(points)-ChartRuns:]
	}
	c := Chart{Top: chartTop, Bottom: chartBottom}
	if len(points) == 0 {
		return c
	}
	totals := make([]int, len(points))
	for i, p := range points {
		for _, k := range KindOrder {
			totals[i] += p.Counts[k]
		}
		c.MaxChanges = max(c.MaxChanges, totals[i])
		c.MaxAssets = max(c.MaxAssets, p.HostsUp, p.Services)
	}
	plotH := chartBottom - chartTop
	slot := (chartRight - chartLeft) / float64(len(points))
	barW := slot * 0.6
	var hosts, svcs []string
	for i, p := range points {
		b := Bar{
			RunID: p.RunID, SlotX: chartLeft + float64(i)*slot, SlotW: slot,
			W: barW, Total: totals[i],
		}
		b.X = b.SlotX + (slot-barW)/2
		b.LabelX = b.SlotX + slot/2
		y := chartBottom
		var parts []string
		for _, k := range KindOrder {
			n := p.Counts[k]
			if n == 0 {
				continue
			}
			h := plotH * float64(n) / float64(c.MaxChanges)
			y -= h
			b.Segments = append(b.Segments, Segment{Kind: k, Count: n, Y: y, H: h})
			parts = append(parts, kindShort[k]+" "+strconv.Itoa(n))
		}
		if len(parts) == 0 {
			parts = []string{"brak zmian"}
		}
		b.Title = fmt.Sprintf("przebieg #%d, %s: %s; hosty aktywne %d, usługi %d",
			p.RunID, p.StartedAt.Local().Format("2006-01-02 15:04"), strings.Join(parts, ", "), p.HostsUp, p.Services)
		c.Bars = append(c.Bars, b)
		hosts = append(hosts, point(b.LabelX, assetY(p.HostsUp, c.MaxAssets)))
		svcs = append(svcs, point(b.LabelX, assetY(p.Services, c.MaxAssets)))
	}
	c.HostsLine, c.ServicesLine = strings.Join(hosts, " "), strings.Join(svcs, " ")
	return c
}

func assetY(v, maxV int) float64 {
	if maxV == 0 {
		return chartBottom
	}
	return chartBottom - (chartBottom-chartTop)*float64(v)/float64(maxV)
}

func point(x, y float64) string { return fmt.Sprintf("%.1f,%.1f", x, y) }
