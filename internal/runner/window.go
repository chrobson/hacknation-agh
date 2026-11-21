package runner

import "time"

// NextWindow returns the scan window relevant at now: the window containing
// now, or else the next one to open. start and end are offsets from local
// midnight (in now's location). end < start means the window crosses
// midnight (e.g. 22:00-06:00); start == end means the window is always open
// (a 24 h window starting at start). The window is half-open [from, to), so
// now is inside iff !now.Before(from) && now.Before(to).
func NextWindow(now time.Time, start, end time.Duration) (from, to time.Time) {
	start, end = clampDay(start), clampDay(end)
	y, m, d := now.Date()
	loc := now.Location()
	at := func(dayOffset int, off time.Duration) time.Time {
		h := int(off / time.Hour)
		mi := int(off % time.Hour / time.Minute)
		s := int(off % time.Minute / time.Second)
		ns := int(off % time.Second)
		return time.Date(y, m, d+dayOffset, h, mi, s, ns, loc)
	}
	endDays := 0
	if end <= start {
		endDays = 1 // crosses midnight, or a full day when start == end
	}
	for off := -1; off <= 1; off++ {
		f := at(off, start)
		t := at(off+endDays, end)
		if !now.Before(f) && now.Before(t) {
			return f, t
		}
		if now.Before(f) {
			return f, t
		}
	}
	// Unreachable for valid input: day+1's window always starts after now.
	return at(1, start), at(1+endDays, end)
}

// InWindow reports whether now lies inside the window [start, end).
func InWindow(now time.Time, start, end time.Duration) bool {
	from, to := NextWindow(now, start, end)
	return !now.Before(from) && now.Before(to)
}

func clampDay(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d >= 24*time.Hour {
		return 24*time.Hour - time.Nanosecond
	}
	return d
}
