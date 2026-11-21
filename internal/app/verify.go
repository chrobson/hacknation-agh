package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Expected is the lab ground truth (lab/expected/runN.json).
type Expected struct {
	Run     string `json:"run"`
	Network string `json:"network"`
	Infra   []struct {
		IP string `json:"ip"`
	} `json:"infra"`
	Hosts []struct {
		IP       string `json:"ip"`
		Name     string `json:"name"`
		Services []struct {
			Port       int      `json:"port"`
			Proto      string   `json:"proto"`
			Product    string   `json:"product"`
			Version    string   `json:"version"`
			InTop1000  bool     `json:"in_top1000"`
			Detections []string `json:"detections"`
		} `json:"services"`
	} `json:"hosts"`
	Changes []struct {
		Kind      string `json:"kind"`
		IP        string `json:"ip"`
		Port      int    `json:"port"`
		Proto     string `json:"proto"`
		InTop1000 *bool  `json:"in_top1000"`
	} `json:"changes_from_prev"`
}

// LoadExpected reads a lab expectation file.
func LoadExpected(path string) (Expected, error) {
	var e Expected
	b, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return e, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// DetectionAliases maps the detection names used in lab/expected to the
// signature ids that satisfy them.
var DetectionAliases = map[string][]string{
	"staging-vhost":   {"staging-env"},
	"login-panel":     {"login-page"},
	"mqtt-anonymous":  {"mosquitto-mqtt"},
	"ip-camera":       {"iot-webui", "ip-camera"},
	"router-login":    {"iot-webui", "router-login", "login-page"},
	"tomcat":          {"tomcat"},
	"tomcat-manager":  {"tomcat-manager"},
	"haproxy-stats":   {"haproxy-stats"},
	"nats-monitoring": {"nats-monitoring"},
}

func aliases(name string) []string {
	if a, ok := DetectionAliases[name]; ok {
		return a
	}
	return []string{name}
}

// Metric is a precision/recall score over a set of items.
type Metric struct {
	Expected   int      `json:"expected"`
	Found      int      `json:"found"`
	TP         int      `json:"tp"`
	FP         int      `json:"fp"`
	FN         int      `json:"fn"`
	Precision  float64  `json:"precision"`
	Recall     float64  `json:"recall"`
	Missing    []string `json:"missing,omitempty"`
	Unexpected []string `json:"unexpected,omitempty"`
	// RecallTop1000 ignores expected items on ports outside nmap's top 1000
	// (the reference scan cannot see them).
	RecallTop1000 *float64 `json:"recall_top1000,omitempty"`
}

// VerifyReport is the output of `asi verify`.
type VerifyReport struct {
	RunID      int64    `json:"run_id"`
	PrevRunID  int64    `json:"prev_run_id,omitempty"`
	Expected   string   `json:"expected"`
	DurationMS *int64   `json:"duration_ms,omitempty"`
	Hosts      Metric   `json:"hosts"`
	Services   Metric   `json:"services"`
	Detections Metric   `json:"detections"`
	Changes    Metric   `json:"changes"`
	MinScore   float64  `json:"min_score"`
	Pass       bool     `json:"pass"`
	Failures   []string `json:"failures,omitempty"`
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

func score(exp, got map[string]bool, top map[string]bool) Metric {
	m := Metric{Expected: len(exp), Found: len(got)}
	for k := range got {
		if exp[k] {
			m.TP++
		} else {
			m.FP++
			m.Unexpected = append(m.Unexpected, k)
		}
	}
	for k := range exp {
		if !got[k] {
			m.FN++
			m.Missing = append(m.Missing, k)
		}
	}
	sort.Strings(m.Missing)
	sort.Strings(m.Unexpected)
	m.Precision, m.Recall = 1, 1
	if m.Found > 0 {
		m.Precision = round3(float64(m.TP) / float64(m.Found))
	}
	if m.Expected > 0 {
		m.Recall = round3(float64(m.TP) / float64(m.Expected))
	}
	if top != nil {
		n, hit := 0, 0
		for k := range exp {
			if !top[k] {
				continue
			}
			n++
			if got[k] {
				hit++
			}
		}
		r := 1.0
		if n > 0 {
			r = round3(float64(hit) / float64(n))
		}
		m.RecallTop1000 = &r
	}
	return m
}

// Verify compares run runID (0 = newest done run) with the expectation.
func Verify(ctx context.Context, db *pgxpool.Pool, e Expected, path string, runID int64, minScore float64) (VerifyReport, error) {
	rep := VerifyReport{Expected: path, MinScore: minScore}
	var err error
	if runID == 0 {
		if runID, err = LatestDoneRun(ctx, db); err != nil {
			return rep, err
		}
		if runID == 0 {
			return rep, fmt.Errorf("brak zakończonego przebiegu")
		}
	}
	rep.RunID = runID
	_ = db.QueryRow(ctx, `SELECT duration_ms FROM scan_runs WHERE id=$1`, runID).Scan(&rep.DurationMS)
	_ = db.QueryRow(ctx, `SELECT COALESCE(prev_run_id,0) FROM diff_runs WHERE run_id=$1`, runID).Scan(&rep.PrevRunID)

	var network netip.Prefix
	if e.Network != "" {
		network, _ = netip.ParsePrefix(e.Network)
	}
	infra := map[string]bool{}
	for _, i := range e.Infra {
		infra[i.IP] = true
	}
	inScope := func(ip string) bool {
		if infra[ip] {
			return false
		}
		if !network.IsValid() {
			return true
		}
		a, err := netip.ParseAddr(ip)
		return err == nil && network.Contains(a)
	}

	// Ground truth.
	expHosts, expSvcs, topSvcs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	expDets, topDets := map[string]bool{}, map[string]bool{}
	vocab := map[string]string{} // signature id -> expected name
	for _, h := range e.Hosts {
		expHosts[h.IP] = true
		for _, s := range h.Services {
			k := fmt.Sprintf("%s:%d/%s", h.IP, s.Port, s.Proto)
			expSvcs[k] = true
			if s.InTop1000 {
				topSvcs[k] = true
			}
			for _, d := range s.Detections {
				dk := fmt.Sprintf("%s:%d:%s", h.IP, s.Port, d)
				expDets[dk] = true
				if s.InTop1000 {
					topDets[dk] = true
				}
				for _, a := range aliases(d) {
					vocab[a] = d
				}
			}
		}
	}
	// Signatures named in the expectations of any run are scored even when
	// absent from this run's ground truth.
	for name := range DetectionAliases {
		for _, a := range aliases(name) {
			if _, ok := vocab[a]; !ok {
				vocab[a] = name
			}
		}
	}
	expChanges, topChanges := map[string]bool{}, map[string]bool{}
	for _, c := range e.Changes {
		k := changeKey(c.Kind, c.IP, c.Port, c.Proto)
		expChanges[k] = true
		if c.InTop1000 == nil || *c.InTop1000 {
			topChanges[k] = true
		}
	}

	// Observed.
	gotHosts := map[string]bool{}
	rows, err := db.Query(ctx, `SELECT host(ip) FROM host_obs WHERE run_id=$1 AND up`, runID)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return rep, err
		}
		if inScope(ip) {
			gotHosts[ip] = true
		}
	}
	rows.Close()
	gotSvcs := map[string]bool{}
	rows, err = db.Query(ctx, `SELECT host(ip), port, proto FROM services WHERE run_id=$1`, runID)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var ip, proto string
		var port int
		if err := rows.Scan(&ip, &port, &proto); err != nil {
			rows.Close()
			return rep, err
		}
		if inScope(ip) {
			gotSvcs[fmt.Sprintf("%s:%d/%s", ip, port, proto)] = true
		}
	}
	rows.Close()
	gotDets := map[string]bool{}
	rows, err = db.Query(ctx, `SELECT host(s.ip), s.port, d.signature_id FROM detections d JOIN services s ON s.id=d.service_id WHERE s.run_id=$1`, runID)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var ip, sigID string
		var port int
		if err := rows.Scan(&ip, &port, &sigID); err != nil {
			rows.Close()
			return rep, err
		}
		name, ok := vocab[sigID]
		if !ok || !inScope(ip) {
			continue // signatures outside the lab vocabulary are not scored
		}
		dk := fmt.Sprintf("%s:%d:%s", ip, port, name)
		// One signature may satisfy several expected names (iot-webui).
		matched := false
		for en := range DetectionAliases {
			for _, a := range aliases(en) {
				if a == sigID && expDets[fmt.Sprintf("%s:%d:%s", ip, port, en)] {
					gotDets[fmt.Sprintf("%s:%d:%s", ip, port, en)] = true
					matched = true
				}
			}
		}
		if !matched {
			gotDets[dk] = true
		}
	}
	rows.Close()
	gotChanges := map[string]bool{}
	rows, err = db.Query(ctx, `SELECT kind, host(ip), port, proto FROM changes WHERE run_id=$1`, runID)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var kind, ip, proto string
		var port int
		if err := rows.Scan(&kind, &ip, &port, &proto); err != nil {
			rows.Close()
			return rep, err
		}
		if inScope(ip) {
			gotChanges[changeKey(kind, ip, port, proto)] = true
		}
	}
	rows.Close()

	rep.Hosts = score(expHosts, gotHosts, nil)
	rep.Services = score(expSvcs, gotSvcs, topSvcs)
	rep.Detections = score(expDets, gotDets, topDets)
	rep.Changes = score(expChanges, gotChanges, topChanges)

	check := func(name string, v float64) {
		if v < minScore {
			rep.Failures = append(rep.Failures, fmt.Sprintf("%s = %.3f < %.2f", name, v, minScore))
		}
	}
	check("hosts.precision", rep.Hosts.Precision)
	check("hosts.recall", rep.Hosts.Recall)
	check("services.precision", rep.Services.Precision)
	check("services.recall_top1000", *rep.Services.RecallTop1000)
	if rep.PrevRunID != 0 && len(expChanges) > 0 {
		check("changes.recall_top1000", *rep.Changes.RecallTop1000)
	}
	rep.Pass = len(rep.Failures) == 0
	return rep, nil
}

func changeKey(kind, ip string, port int, proto string) string {
	if port == 0 {
		return kind + " " + ip
	}
	return fmt.Sprintf("%s %s:%d/%s", kind, ip, port, proto)
}
