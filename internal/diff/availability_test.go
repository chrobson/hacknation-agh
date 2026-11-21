package diff

import (
	"testing"
	"time"
)

func samplesAt(loc *time.Location, hours []int, seen func(h int) bool) []Sample {
	var out []Sample
	for i, h := range hours {
		at := time.Date(2026, 11, 1+i, h, 0, 0, 0, loc)
		out = append(out, Sample{At: at, Seen: seen(h)})
	}
	return out
}

func TestAnalyzeAlwaysNeverEmpty(t *testing.T) {
	loc := time.UTC
	hours := []int{1, 7, 13, 19, 2, 8}
	a := Analyze(samplesAt(loc, hours, func(int) bool { return true }), loc, 2)
	if a.Pattern != PatternAlways || a.Percent != 100 || a.Seen != 6 || a.Total != 6 {
		t.Errorf("always: %+v", a)
	}
	a = Analyze(samplesAt(loc, hours, func(int) bool { return false }), loc, 2)
	if a.Pattern != PatternNever || a.Percent != 0 || a.Total != 6 {
		t.Errorf("never: %+v", a)
	}
	a = Analyze(nil, loc, 2)
	if a.Pattern != PatternNone || a.Total != 0 {
		t.Errorf("empty: %+v", a)
	}
}

func TestAnalyzeIrregular(t *testing.T) {
	loc := time.UTC
	// Alternating within every band: no band is high or low.
	var ss []Sample
	for i := 0; i < 8; i++ {
		ss = append(ss, Sample{At: time.Date(2026, 11, 1+i, (i%4)*6+1, 0, 0, 0, loc), Seen: (i/4)%2 == 0})
	}
	a := Analyze(ss, loc, 2)
	if a.Pattern != PatternIrregular || a.Percent != 50 || a.Label != "" {
		t.Errorf("irregular: %+v", a)
	}
}

func TestAnalyzeDayOnlyWarsaw(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("tzdata:", err)
	}
	hours := []int{10, 23, 10, 23, 10, 23}
	ss := samplesAt(loc, hours, func(h int) bool { return h == 10 })
	// Pass UTC instants: banding must use the given location.
	for i := range ss {
		ss[i].At = ss[i].At.UTC()
	}
	a := Analyze(ss, loc, 2)
	if a.Pattern != PatternTimeOfDay {
		t.Fatalf("pattern %q: %+v", a.Pattern, a)
	}
	if a.Label != "odpowiada głównie w godz. 06-12" {
		t.Errorf("label %q", a.Label)
	}
	if a.Bands[1] != (Band{From: 6, To: 12, Seen: 3, Total: 3}) || a.Bands[3] != (Band{From: 18, To: 24, Seen: 0, Total: 3}) {
		t.Errorf("bands %+v", a.Bands)
	}
	if a.Percent != 50 || a.Bands[1].Level() != "hi" || a.Bands[3].Level() != "lo" || a.Bands[0].Level() != "none" {
		t.Errorf("percent/levels: %+v", a)
	}
}

func TestAnalyzeTooFewPerBand(t *testing.T) {
	loc := time.UTC
	// One sample per band only: never "pora dnia".
	a := Analyze(samplesAt(loc, []int{10, 23}, func(h int) bool { return h == 10 }), loc, 2)
	if a.Pattern != PatternIrregular {
		t.Errorf("too few: %+v", a)
	}
	// Two in the day band but one at night: still not enough.
	a = Analyze(samplesAt(loc, []int{10, 11, 23}, func(h int) bool { return h < 12 }), loc, 2)
	if a.Pattern == PatternTimeOfDay {
		t.Errorf("too few at night: %+v", a)
	}
}

func TestAnalyzeMergesAdjacentBands(t *testing.T) {
	loc := time.UTC
	hours := []int{7, 8, 13, 14, 19, 20, 1, 2}
	a := Analyze(samplesAt(loc, hours, func(h int) bool { return h >= 6 && h < 18 }), loc, 2)
	if a.Pattern != PatternTimeOfDay || a.Label != "odpowiada głównie w godz. 06-18" {
		t.Errorf("06-18: %+v", a)
	}
	// High at night across midnight: 18-24 and 00-06 merge to 18-06.
	a = Analyze(samplesAt(loc, hours, func(h int) bool { return h >= 18 || h < 6 }), loc, 2)
	if a.Pattern != PatternTimeOfDay || a.Label != "odpowiada głównie w godz. 18-06" {
		t.Errorf("18-06: %+v", a)
	}
	// Two separate high bands.
	a = Analyze(samplesAt(loc, hours, func(h int) bool { return h < 6 || (h >= 12 && h < 18) }), loc, 2)
	if a.Label != "odpowiada głównie w godz. 00-06, 12-18" {
		t.Errorf("split: %+v", a)
	}
}

func TestHistoryRuns(t *testing.T) {
	for in, want := range map[string]int{"": 30, "x": 30, "1": 5, "50": 50, "1000": 100} {
		if got := historyRuns(map[string][]string{"runs": {in}}); got != want {
			t.Errorf("runs=%q: %d want %d", in, got, want)
		}
	}
}
