// Package safety measures what a scan run actually sent (nmap packets and
// elapsed time, HTTP requests per method, requests carrying credentials,
// peak HTTP rate) and re-checks every scanned address against the
// allowlist. The result is a per-run safety receipt stored in run_safety,
// shown on the run page and served as JSON (GET /runs/{id}/safety.json,
// `asi audit <run>`).
//
// The meter travels in the context: the runner attaches one per run and the
// nmap wrapper and the HTTP transport record into it. Code that runs without
// a meter (tests, imports) records nothing.
package safety

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// SampleArgv is how many nmap command lines are kept verbatim in the
// receipt (the hash covers all of them).
const SampleArgv = 4

// Invocation is one nmap execution as measured by the wrapper.
type Invocation struct {
	Argv    []string      // full command line without the binary
	Packets int64         // raw packets nmap reported, plus estimated connect() probes
	Raw     bool          // nmap printed "Raw packets sent" for this run
	Elapsed time.Duration // nmap's own elapsed time (<runstats>), wall time if missing
	Start   time.Time
	End     time.Time
	Targets []netip.Prefix // target operands of the command line
}

// Meter accumulates the measurements of one run. It is safe for concurrent
// use by the workers and the HTTP probes.
type Meter struct {
	mu sync.Mutex

	invocations int
	rawReported int
	packets     int64
	elapsed     time.Duration
	first, last time.Time
	busy        []span // merged [start,end) intervals with nmap running
	peakInvPPS  float64
	argvHash    hash.Hash
	argvSample  []string
	targets     []netip.Prefix

	httpGet, httpHead, httpOther int64
	httpAuth                     int64
	window                       []time.Time // request times of the last second
	peakRPS                      int

	now func() time.Time
}

type span struct{ a, b time.Time }

// NewMeter returns an empty meter.
func NewMeter() *Meter { return &Meter{argvHash: sha256.New(), now: time.Now} }

type ctxKey struct{}

// WithMeter returns ctx carrying m.
func WithMeter(ctx context.Context, m *Meter) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, m)
}

// From returns the meter of ctx or nil.
func From(ctx context.Context) *Meter {
	if ctx == nil {
		return nil
	}
	m, _ := ctx.Value(ctxKey{}).(*Meter)
	return m
}

// MinPeakElapsed is the shortest nmap invocation used for the per-invocation
// peak rate: --max-rate is an average, so a 10 ms run sending 5 packets says
// nothing about the cap.
const MinPeakElapsed = time.Second

// AddNmap records one nmap invocation.
func (m *Meter) AddNmap(inv Invocation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invocations++
	if inv.Raw {
		m.rawReported++
	}
	m.packets += inv.Packets
	m.elapsed += inv.Elapsed
	if m.first.IsZero() || inv.Start.Before(m.first) {
		m.first = inv.Start
	}
	if inv.End.After(m.last) {
		m.last = inv.End
	}
	if inv.End.After(inv.Start) {
		m.busy = mergeSpan(m.busy, span{inv.Start, inv.End})
	}
	if inv.Elapsed >= MinPeakElapsed {
		if pps := float64(inv.Packets) / inv.Elapsed.Seconds(); pps > m.peakInvPPS {
			m.peakInvPPS = pps
		}
	}
	line := strings.Join(inv.Argv, " ")
	m.argvHash.Write([]byte(line))
	m.argvHash.Write([]byte{'\n'})
	if len(m.argvSample) < SampleArgv {
		m.argvSample = append(m.argvSample, line)
	}
	m.targets = append(m.targets, inv.Targets...)
}

// mergeSpan inserts s into a sorted list of disjoint spans.
func mergeSpan(ss []span, s span) []span {
	out := make([]span, 0, len(ss)+1)
	placed := false
	for _, x := range ss {
		switch {
		case x.b.Before(s.a):
			out = append(out, x)
		case s.b.Before(x.a):
			if !placed {
				out = append(out, s)
				placed = true
			}
			out = append(out, x)
		default:
			if x.a.Before(s.a) {
				s.a = x.a
			}
			if x.b.After(s.b) {
				s.b = x.b
			}
		}
	}
	if !placed {
		out = append(out, s)
	}
	return out
}

// CountHTTP records one outgoing HTTP request.
func (m *Meter) CountHTTP(req *http.Request) {
	if m == nil || req == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch req.Method {
	case http.MethodGet, "":
		m.httpGet++
	case http.MethodHead:
		m.httpHead++
	default:
		m.httpOther++
	}
	if carriesAuth(req.Header) {
		m.httpAuth++
	}
	now := m.now()
	cut := now.Add(-time.Second)
	i := 0
	for i < len(m.window) && !m.window[i].After(cut) {
		i++
	}
	m.window = append(m.window[i:], now)
	if len(m.window) > m.peakRPS {
		m.peakRPS = len(m.window)
	}
}

// carriesAuth reports a request sending credentials: an Authorization or
// Proxy-Authorization header, or any Cookie.
func carriesAuth(h http.Header) bool {
	return h.Get("Authorization") != "" || h.Get("Proxy-Authorization") != "" || h.Get("Cookie") != ""
}

// Transport wraps base so every request is counted in the meter of its
// context.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return countingTransport{base: base}
}

type countingTransport struct{ base http.RoundTripper }

func (t countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	From(req.Context()).CountHTTP(req)
	return t.base.RoundTrip(req)
}

// Allowlist is the subset of target.Allowlist the receipt needs.
type Allowlist interface {
	AllowsAddr(netip.Addr) bool
	AllowsPrefix(netip.Prefix) bool
}

// Receipt is the stored and displayed safety record of one run.
type Receipt struct {
	RunID int64 `json:"run_id"`

	NmapInvocations   int      `json:"nmap_invocations"`
	NmapRawReported   int      `json:"nmap_raw_reported"`
	NmapPackets       int64    `json:"nmap_packets"`
	NmapElapsedMs     int64    `json:"nmap_elapsed_ms"`
	NmapBusyMs        int64    `json:"nmap_busy_ms"`
	NmapPeakInvPPS    float64  `json:"nmap_peak_invocation_pps"`
	ConfiguredMaxRate int      `json:"configured_max_rate"`
	PerWorkerRate     int      `json:"per_worker_rate"`
	ArgvSHA256        string   `json:"argv_sha256"`
	ArgvSample        []string `json:"argv_sample"`

	HTTPGet       int64   `json:"http_get"`
	HTTPHead      int64   `json:"http_head"`
	HTTPOther     int64   `json:"http_other"`
	HTTPAuth      int64   `json:"http_auth_headers"`
	HTTPPeakRPS   float64 `json:"http_peak_rps"`
	HTTPRateLimit float64 `json:"http_rate_limit"`
	HTTPBurst     int     `json:"http_burst"`

	TargetsChecked          int64 `json:"targets_checked"`
	TargetsOutsideAllowlist int64 `json:"targets_outside_allowlist"`

	UpdatedAt time.Time `json:"updated_at"`
}

// EffectivePPS is the run's average nmap rate: packets over the time at
// least one nmap process was running. All workers share configured_max_rate
// (each gets max_rate/K), so this is the number to compare with the cap.
func (r Receipt) EffectivePPS() float64 {
	if r.NmapBusyMs <= 0 {
		return 0
	}
	return float64(r.NmapPackets) / (float64(r.NmapBusyMs) / 1000)
}

// Checks are the pass/fail rows of the receipt.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Snapshot builds the receipt; allow re-checks every target operand passed
// to nmap (nil skips the check).
func (m *Meter) Snapshot(allow Allowlist) Receipt {
	var r Receipt
	if m == nil {
		return r
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r.NmapInvocations = m.invocations
	r.NmapRawReported = m.rawReported
	r.NmapPackets = m.packets
	r.NmapElapsedMs = m.elapsed.Milliseconds()
	var busy time.Duration
	for _, s := range m.busy {
		busy += s.b.Sub(s.a)
	}
	r.NmapBusyMs = busy.Milliseconds()
	r.NmapPeakInvPPS = m.peakInvPPS
	if m.invocations > 0 {
		r.ArgvSHA256 = hex.EncodeToString(m.argvHash.Sum(nil))
	}
	r.ArgvSample = append([]string(nil), m.argvSample...)
	r.HTTPGet, r.HTTPHead, r.HTTPOther, r.HTTPAuth = m.httpGet, m.httpHead, m.httpOther, m.httpAuth
	r.HTTPPeakRPS = float64(m.peakRPS)
	if allow != nil {
		for _, p := range m.targets {
			n := addrCount(p)
			r.TargetsChecked += n
			if !allow.AllowsPrefix(p) {
				r.TargetsOutsideAllowlist += n
			}
		}
	}
	return r
}

// addrCount is the number of addresses in p, capped for huge IPv6 prefixes.
func addrCount(p netip.Prefix) int64 {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 62 {
		return 1 << 62
	}
	return 1 << host
}
