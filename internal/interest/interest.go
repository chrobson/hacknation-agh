// Package interest computes a transparent 0-100 "interest" score for a
// service: a deterministic sum of the rules below, built only from data the
// scan already stored (detections, nmap service, TLS facts, changes and the
// analyst annotation). It is a triage aid for "what to look at first", not a
// vulnerability assessment.
//
// Rule table (all points are additive, the total is capped at 100):
//
//	a) detection severity   highest of points(sev) x confidence/100:
//	                        Critical 60, High 45, Medium 25, Low 10, Info 0
//	b) category (once each) admin-panel +20, staging +15, iot +15, cms +5
//	c) outdated version     +15 (any detection with evidence "outdated")
//	d) exposed service      only the highest class applies, matched by the
//	                        nmap service name first and the port second:
//	                        docker API +40, telnet +30, database/cache +20,
//	                        remote desktop +20, ftp +15, message broker +10
//	e) TLS                  expired certificate +10, self-signed +5,
//	                        login form or admin panel over plain HTTP +10
//	f) change context       new service +15, changed +5, unstable host +5
//	g) analyst              false positive: score 0; analyst severity sets a
//	                        floor (Critical 90, High 70, Medium 40, Low 15);
//	                        Info caps the score at 10
package interest

import (
	"fmt"
	"sort"
	"strings"
)

// Detection is the part of a signature match the score uses. Signature is
// the signature id; Severity is the effective default severity (as in the
// DefectDojo export).
type Detection struct {
	Signature, Name, Category, Severity string
	Confidence                          int
	Outdated                            string
}

// Input is everything known about one service. Service is the nmap
// service name (the banner column).
type Input struct {
	Port                      int
	Proto, Service, Product   string
	Scheme                    string
	Detections                []Detection
	TLSExpired, TLSSelfSigned bool
	ChangeKinds               []string
	HostUnstable              bool
	AnalystSeverity           string
	FalsePositive             bool
}

// Reason is one rule that contributed points.
type Reason struct {
	Label  string
	Points int
}

// Result is the score with its level and the contributing rules, highest
// first.
type Result struct {
	Score   int
	Level   string
	Reasons []Reason
}

// Labels joins the reason labels with their points, for a tooltip.
func (r Result) Labels() string {
	parts := make([]string, 0, len(r.Reasons))
	for _, x := range r.Reasons {
		if x.Points != 0 {
			parts = append(parts, fmt.Sprintf("%s (+%d)", x.Label, x.Points))
		} else {
			parts = append(parts, x.Label)
		}
	}
	return strings.Join(parts, "; ")
}

// Top returns at most n reasons.
func (r Result) Top(n int) []Reason {
	if len(r.Reasons) <= n {
		return r.Reasons
	}
	return r.Reasons[:n]
}

// Rule weights, see the package comment.
var (
	severityPoints = map[string]int{"critical": 60, "high": 45, "medium": 25, "low": 10, "info": 0}
	categoryRules  = []struct {
		cat, label string
		points     int
	}{
		{"admin-panel", "panel administracyjny", 20},
		{"staging", "środowisko testowe", 15},
		{"iot", "urządzenie IoT", 15},
		{"cms", "CMS", 5},
	}
	analystFloor = map[string]int{"critical": 90, "high": 70, "medium": 40, "low": 15}
)

const (
	pointsOutdated   = 15
	pointsTLSExpired = 10
	pointsSelfSigned = 5
	pointsLoginHTTP  = 10
	pointsNew        = 15
	pointsChanged    = 5
	pointsUnstable   = 5
	analystInfoCap   = 10
	maxScore         = 100
)

// serviceClass is an exposed service type that is interesting by itself.
type serviceClass struct {
	label    string
	points   int
	services []string // nmap service names
	ports    []int    // fallback when nmap did not name the service
}

var serviceClasses = []serviceClass{
	{"API Dockera bez TLS", 40, []string{"docker"}, []int{2375}},
	{"telnet (bez szyfrowania)", 30, []string{"telnet"}, []int{23}},
	{"baza danych lub cache dostępne z sieci", 20,
		[]string{"postgresql", "mysql", "ms-sql-s", "oracle", "oracle-tns", "mongodb", "mongod", "redis", "memcached", "memcache",
			"elasticsearch", "couchdb", "cassandra"},
		[]int{5432, 3306, 1433, 1521, 27017, 6379, 11211, 9200}},
	{"zdalny pulpit", 20, []string{"ms-wbt-server", "vnc"}, []int{3389, 5900}},
	{"FTP", 15, []string{"ftp"}, []int{21}},
	{"broker wiadomości", 10, []string{"amqp", "mqtt"}, []int{5672, 1883}},
}

// matchClass returns the class of the service: by nmap service name first
// (so PostgreSQL on 15432 counts), then by well-known port (nmap reports
// Elasticsearch on 9200 as "http"). Classes are ordered by points, so the
// first match is the highest.
func matchClass(service string, port int) (serviceClass, bool) {
	svc := strings.ToLower(strings.TrimSpace(service))
	svc = strings.TrimSuffix(svc, "?")
	for _, c := range serviceClasses {
		for _, s := range c.services {
			if svc == s {
				return c, true
			}
		}
	}
	for _, c := range serviceClasses {
		for _, p := range c.ports {
			if port == p {
				return c, true
			}
		}
	}
	return serviceClass{}, false
}

// Score evaluates the rules for one service.
func Score(in Input) Result {
	if in.FalsePositive {
		return Result{Score: 0, Level: level(0), Reasons: []Reason{{Label: "oznaczone jako fałszywy alarm"}}}
	}
	var reasons []Reason
	add := func(label string, pts int) {
		if pts > 0 {
			reasons = append(reasons, Reason{Label: label, Points: pts})
		}
	}

	// a) highest detection severity weighted by confidence
	best, bestLabel := 0, ""
	for _, d := range in.Detections {
		conf := d.Confidence
		if conf < 0 {
			conf = 0
		}
		if conf > 100 {
			conf = 100
		}
		p := severityPoints[strings.ToLower(d.Severity)] * conf / 100
		if p > best {
			best, bestLabel = p, fmt.Sprintf("detekcja %s: poziom %s", d.Name, d.Severity)
		}
	}
	add(bestLabel, best)

	// b) categories, once each
	for _, c := range categoryRules {
		for _, d := range in.Detections {
			if d.Category == c.cat {
				add(c.label, c.points)
				break
			}
		}
	}

	// c) outdated version
	for _, d := range in.Detections {
		if d.Outdated != "" {
			add(fmt.Sprintf("nieaktualna wersja (%s)", d.Outdated), pointsOutdated)
			break
		}
	}

	// d) exposed service class
	if c, ok := matchClass(in.Service, in.Port); ok {
		add(c.label, c.points)
	}

	// e) TLS
	if in.TLSExpired {
		add("wygasły certyfikat TLS", pointsTLSExpired)
	}
	if in.TLSSelfSigned {
		add("samopodpisany certyfikat TLS", pointsSelfSigned)
	}
	if strings.EqualFold(in.Scheme, "http") {
		for _, d := range in.Detections {
			if d.Category == "admin-panel" || d.Signature == "login-page" {
				add("logowanie bez TLS", pointsLoginHTTP)
				break
			}
		}
	}

	// f) change context
	var isNew, changed, unstable bool
	for _, k := range in.ChangeKinds {
		switch k {
		case "new":
			isNew = true
		case "changed":
			changed = true
		case "unstable":
			unstable = true
		}
	}
	if isNew {
		add("nowa usługa w tym przebiegu", pointsNew)
	}
	if changed {
		add("zmieniona usługa", pointsChanged)
	}
	if unstable || in.HostUnstable {
		add("niestabilny host", pointsUnstable)
	}

	total := 0
	for _, r := range reasons {
		total += r.Points
	}
	if total > maxScore {
		total = maxScore
	}

	// g) analyst severity: floor, or cap for Info
	sev := strings.ToLower(strings.TrimSpace(in.AnalystSeverity))
	if floor, ok := analystFloor[sev]; ok && total < floor {
		reasons = append(reasons, Reason{Label: "poziom ustawiony przez analityka", Points: floor - total})
		total = floor
	} else if sev == "info" && total > analystInfoCap {
		total = analystInfoCap
		reasons = append(reasons, Reason{Label: "analityk: poziom informacyjny (ocena ograniczona do 10)"})
	}

	sort.SliceStable(reasons, func(i, j int) bool { return reasons[i].Points > reasons[j].Points })
	return Result{Score: total, Level: level(total), Reasons: reasons}
}

func level(score int) string {
	switch {
	case score >= 60:
		return "wysoki"
	case score >= 30:
		return "średni"
	case score >= 1:
		return "niski"
	}
	return "brak"
}
