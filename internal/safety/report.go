package safety

import (
	"fmt"
	"math"
)

// Report is the receipt with derived values and the pass/fail checks: the
// body of GET /runs/{id}/safety.json and of `asi audit <run>`.
type Report struct {
	Receipt
	EffectivePPS float64  `json:"effective_pps"`
	OK           bool     `json:"ok"`
	Checks       []Check  `json:"checks"`
	Notes        []string `json:"notes"`
}

// BuildReport derives the checks from r.
func BuildReport(r Receipt) Report {
	rep := Report{Receipt: r, EffectivePPS: round1(r.EffectivePPS()), OK: true}
	add := func(name string, ok bool, format string, a ...any) {
		rep.Checks = append(rep.Checks, Check{Name: name, OK: ok, Detail: fmt.Sprintf(format, a...)})
		rep.OK = rep.OK && ok
	}
	if r.ConfiguredMaxRate > 0 {
		add("nmap_rate", rep.EffectivePPS <= float64(r.ConfiguredMaxRate),
			"%.1f pakietów/s (%d pakietów w %.1f s pracy nmap) przy limicie %d/s",
			rep.EffectivePPS, r.NmapPackets, float64(r.NmapBusyMs)/1000, r.ConfiguredMaxRate)
	} else {
		add("nmap_rate", true, "%.1f pakietów/s (%d pakietów); limit max_rate nie ustawiony",
			rep.EffectivePPS, r.NmapPackets)
	}
	add("http_methods", r.HTTPOther == 0, "GET %d · HEAD %d · inne %d", r.HTTPGet, r.HTTPHead, r.HTTPOther)
	add("http_auth", r.HTTPAuth == 0, "%d żądań z nagłówkiem Authorization/Cookie", r.HTTPAuth)
	if r.HTTPRateLimit > 0 {
		capRPS := r.HTTPRateLimit + float64(r.HTTPBurst)
		add("http_rate", r.HTTPPeakRPS <= capRPS,
			"szczyt %.0f żądań w oknie 1 s przy limicie %.0f/s + zapas %d", r.HTTPPeakRPS, r.HTTPRateLimit, r.HTTPBurst)
	}
	add("allowlist", r.TargetsOutsideAllowlist == 0,
		"%d adresów sprawdzonych ponownie po przebiegu, %d poza listą dozwolonych", r.TargetsChecked, r.TargetsOutsideAllowlist)

	if r.NmapRawReported < r.NmapInvocations {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d z %d wywołań nmap nie podało licznika pakietów (skan bez uprawnień raw): ich pakiety są szacowane z XML (adresy × porty/sondy).",
			r.NmapInvocations-r.NmapRawReported, r.NmapInvocations))
	}
	rep.Notes = append(rep.Notes,
		"Średnia liczona na czas, w którym działał co najmniej jeden proces nmap; K procesów dostaje po max_rate/K, więc w przedziałach krótszych niż 1 s chwilowe tempo może przekroczyć limit.",
		"Sondy wykrywania wersji (-sV) idą przez zwykłe połączenia TCP i nie są objęte licznikiem pakietów nmap ani --max-rate.")
	return rep
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
