package diff

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Sample is one covering run of an asset: when it started and whether the
// asset was seen in it.
type Sample struct {
	At   time.Time
	Seen bool
}

// Band is a six-hour time-of-day band [From, To) with its counts.
type Band struct {
	From, To    int
	Seen, Total int
}

// Rate returns Seen/Total in percent (floor), 0 for an empty band.
func (b Band) Rate() int {
	if b.Total == 0 {
		return 0
	}
	return b.Seen * 100 / b.Total
}

// Level classifies the band for shading: none (no runs), hi (>= 80%),
// lo (<= 20%) or mid.
func (b Band) Level() string {
	switch {
	case b.Total == 0:
		return "none"
	case b.Seen*5 >= b.Total*4:
		return "hi"
	case b.Seen*5 <= b.Total:
		return "lo"
	}
	return "mid"
}

// Patterns returned by Analyze.
const (
	PatternNone      = "brak danych"
	PatternAlways    = "zawsze"
	PatternNever     = "nigdy"
	PatternTimeOfDay = "pora dnia"
	PatternIrregular = "nieregularnie"
)

// DefaultMinPerBand is the number of covering runs a band needs before it
// can take part in the time-of-day pattern.
const DefaultMinPerBand = 2

// Availability summarises the covering runs of one asset.
type Availability struct {
	Seen, Total, Percent int
	Bands                [4]Band
	Pattern, Label       string
}

// Analyze computes availability and the time-of-day pattern. Samples are
// put into four bands by the local hour of At in loc (00-06, 06-12, 12-18,
// 18-24). The pattern is:
//   - "zawsze" when the asset was seen in every sample;
//   - "nigdy" when it was never seen;
//   - "pora dnia" when at least two bands have >= minPerBand samples each,
//     one of them with rate >= 80% and another with rate <= 20%; Label then
//     names the high bands, adjacent ones merged ("odpowiada głównie w godz.
//     06-18");
//   - "nieregularnie" otherwise.
func Analyze(samples []Sample, loc *time.Location, minPerBand int) Availability {
	if loc == nil {
		loc = time.Local
	}
	minPerBand = max(minPerBand, 1)
	var a Availability
	for i := range a.Bands {
		a.Bands[i].From, a.Bands[i].To = i*6, i*6+6
	}
	for _, s := range samples {
		b := &a.Bands[s.At.In(loc).Hour()/6]
		b.Total++
		a.Total++
		if s.Seen {
			b.Seen++
			a.Seen++
		}
	}
	switch {
	case a.Total == 0:
		a.Pattern = PatternNone
		return a
	case a.Seen == a.Total:
		a.Percent, a.Pattern = 100, PatternAlways
		return a
	case a.Seen == 0:
		a.Pattern, a.Label = PatternNever, "nie odpowiada w żadnym przebiegu"
		return a
	}
	a.Percent = a.Seen * 100 / a.Total
	a.Pattern = PatternIrregular

	var eligible, high [4]bool
	n, anyHigh, anyLow := 0, false, false
	for i, b := range a.Bands {
		if b.Total < minPerBand {
			continue
		}
		eligible[i] = true
		n++
		switch b.Level() {
		case "hi":
			high[i], anyHigh = true, true
		case "lo":
			anyLow = true
		}
	}
	if n >= 2 && anyHigh && anyLow {
		a.Pattern = PatternTimeOfDay
		a.Label = "odpowiada głównie w godz. " + strings.Join(bandRanges(high), ", ")
	}
	return a
}

// bandRanges formats runs of adjacent high bands as "HH-HH", treating the
// day as circular (18-24 followed by 00-06 is "18-06").
func bandRanges(high [4]bool) []string {
	all := true
	for _, h := range high {
		all = all && h
	}
	if all {
		return []string{"00-24"}
	}
	// Start right after a low band so a run crossing midnight stays whole.
	start := 0
	for i := range high {
		if !high[i] {
			start = (i + 1) % 4
			break
		}
	}
	var out []string
	for j := 0; j < 4; {
		i := (start + j) % 4
		if !high[i] {
			j++
			continue
		}
		k := j
		for k < 4 && high[(start+k)%4] {
			k++
		}
		from, to := i*6, ((start+k-1)%4)*6+6
		out = append(out, fmt.Sprintf("%02d-%02d", from, to))
		j = k
	}
	slices.Sort(out)
	return out
}
