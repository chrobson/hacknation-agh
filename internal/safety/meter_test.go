package safety

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

type allowAll struct{ p netip.Prefix }

func (a allowAll) AllowsAddr(ip netip.Addr) bool { return a.p.Contains(ip) }
func (a allowAll) AllowsPrefix(q netip.Prefix) bool {
	return a.p.Bits() <= q.Bits() && a.p.Contains(q.Addr())
}

func TestTransportCountsPerContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: Transport(http.DefaultTransport)}
	m := NewMeter()
	ctx := WithMeter(context.Background(), m)
	for _, method := range []string{"GET", "HEAD", "GET", "OPTIONS"} {
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL, nil)
		if method == "OPTIONS" {
			req.Header.Set("Cookie", "a=b")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// Without a meter nothing is recorded and nothing breaks.
	req, _ := http.NewRequest("GET", srv.URL, nil)
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	r := m.Snapshot(nil)
	if r.HTTPGet != 2 || r.HTTPHead != 1 || r.HTTPOther != 1 || r.HTTPAuth != 1 {
		t.Errorf("counts %+v", r)
	}
	if r.HTTPPeakRPS != 4 {
		t.Errorf("peak rps %v", r.HTTPPeakRPS)
	}
}

func TestSlidingWindowPeak(t *testing.T) {
	m := NewMeter()
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	req, _ := http.NewRequest("GET", "http://x/", nil)
	for i := 0; i < 30; i++ { // 10 per second for 3 s
		m.CountHTTP(req)
		now = now.Add(100 * time.Millisecond)
	}
	if got := m.Snapshot(nil).HTTPPeakRPS; got != 10 {
		t.Errorf("peak = %v, want 10", got)
	}
}

func TestNmapAggregationAndChecks(t *testing.T) {
	m := NewMeter()
	t0 := time.Unix(0, 0)
	// Two parallel workers of 4 s each overlapping by 2 s: busy 6 s.
	m.AddNmap(Invocation{Argv: []string{"-sn", "10.20.0.0/24"}, Packets: 1200, Raw: true, Elapsed: 4 * time.Second,
		Start: t0, End: t0.Add(4 * time.Second), Targets: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}})
	m.AddNmap(Invocation{Argv: []string{"-sn", "10.20.1.0/24"}, Packets: 600, Elapsed: 4 * time.Second,
		Start: t0.Add(2 * time.Second), End: t0.Add(6 * time.Second), Targets: []netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")}})
	r := m.Snapshot(allowAll{netip.MustParsePrefix("10.20.0.0/18")})
	if r.NmapBusyMs != 6000 || r.NmapPackets != 1800 || r.NmapRawReported != 1 || r.NmapInvocations != 2 {
		t.Fatalf("%+v", r)
	}
	if r.EffectivePPS() != 300 || r.NmapPeakInvPPS != 300 {
		t.Errorf("pps %v peak %v", r.EffectivePPS(), r.NmapPeakInvPPS)
	}
	if r.TargetsChecked != 512 || r.TargetsOutsideAllowlist != 0 || len(r.ArgvSHA256) != 64 || len(r.ArgvSample) != 2 {
		t.Errorf("%+v", r)
	}
	r.ConfiguredMaxRate, r.HTTPRateLimit, r.HTTPBurst = 1000, 20, 5
	if rep := BuildReport(r); !rep.OK || len(rep.Checks) != 5 {
		t.Errorf("report %+v", rep)
	}
	r.ConfiguredMaxRate = 200
	if rep := BuildReport(r); rep.OK {
		t.Error("300 pps over a 200 cap must fail")
	}
	r.ConfiguredMaxRate, r.HTTPOther = 1000, 1
	if rep := BuildReport(r); rep.OK {
		t.Error("a non GET/HEAD request must fail")
	}
}
