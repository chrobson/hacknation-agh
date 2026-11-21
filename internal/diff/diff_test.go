package diff

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
)

var testCfg = Config{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func svc(run int64, addr string, port uint16, product, version string) model.ServiceObs {
	return model.ServiceObs{RunID: run, Key: model.AssetKey{IP: ip(addr), Port: port, Proto: "tcp"}, Product: product, Version: version}
}

// fmtChange renders a change compactly for comparisons.
func fmtChange(c model.Change) string {
	s := fmt.Sprintf("%s %s", c.Kind, KeyString(c.Key))
	if c.Field != "" {
		s += " " + c.Field
	}
	if c.Old != "" || c.New != "" {
		s += fmt.Sprintf(" %q->%q", c.Old, c.New)
	}
	return s
}

func fmtChanges(cs []model.Change) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, fmtChange(c))
	}
	return out
}

func TestCompareServices(t *testing.T) {
	base := svc(1, "10.0.0.1", 22, "OpenSSH", "7.4")
	tests := []struct {
		name       string
		prev, curr []model.ServiceObs
		want       []string
	}{
		{"identical", []model.ServiceObs{base}, []model.ServiceObs{base}, []string{}},
		{"both empty", nil, nil, []string{}},
		{"new", nil, []model.ServiceObs{base}, []string{`new 10.0.0.1:22/tcp ""->"OpenSSH 7.4"`}},
		{"gone", []model.ServiceObs{base}, nil, []string{`gone 10.0.0.1:22/tcp "OpenSSH 7.4"->""`}},
		{
			"version changed",
			[]model.ServiceObs{base},
			[]model.ServiceObs{svc(2, "10.0.0.1", 22, "OpenSSH", "8.9p1")},
			[]string{`changed 10.0.0.1:22/tcp version "7.4"->"8.9p1"`},
		},
		{
			"every field changed gives one change per field",
			[]model.ServiceObs{{Key: base.Key, Product: "a", Version: "1", ExtraInfo: "x", CPE: "cpe:/a", Banner: "b1"}},
			[]model.ServiceObs{{Key: base.Key, Product: "b", Version: "2", ExtraInfo: "y", CPE: "cpe:/b", Banner: "b2"}},
			[]string{
				`changed 10.0.0.1:22/tcp product "a"->"b"`,
				`changed 10.0.0.1:22/tcp version "1"->"2"`,
				`changed 10.0.0.1:22/tcp extrainfo "x"->"y"`,
				`changed 10.0.0.1:22/tcp cpe "cpe:/a"->"cpe:/b"`,
				`changed 10.0.0.1:22/tcp banner "b1"->"b2"`,
			},
		},
		{
			"vhost and proto are part of the key",
			[]model.ServiceObs{{Key: model.AssetKey{IP: ip("10.0.0.1"), Port: 80, Proto: "tcp", VHost: "a.example"}}},
			[]model.ServiceObs{
				{Key: model.AssetKey{IP: ip("10.0.0.1"), Port: 80, Proto: "tcp", VHost: "b.example"}},
				{Key: model.AssetKey{IP: ip("10.0.0.1"), Port: 80, Proto: "udp", VHost: "a.example"}},
			},
			[]string{
				`gone 10.0.0.1:80/tcp (a.example)`,
				`new 10.0.0.1:80/tcp (b.example)`,
				`new 10.0.0.1:80/udp (a.example)`,
			},
		},
		{
			"ipv4-mapped addresses match plain ipv4",
			[]model.ServiceObs{{Key: model.AssetKey{IP: ip("::ffff:10.0.0.1"), Port: 22, Proto: "tcp"}}},
			[]model.ServiceObs{{Key: model.AssetKey{IP: ip("10.0.0.1"), Port: 22, Proto: "tcp"}}},
			[]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareServices(tt.prev, tt.curr)
			SortChanges(got)
			if g := fmtChanges(got); !reflect.DeepEqual(g, tt.want) {
				t.Errorf("got  %q\nwant %q", g, tt.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	f := func(ups ...bool) []model.Flip {
		out := make([]model.Flip, len(ups))
		for i, u := range ups {
			out[i] = model.Flip{RunID: int64(i + 1), Up: u}
		}
		return out
	}
	tests := []struct {
		name   string
		flips  []model.Flip
		misses int
		cfg    Config
		want   model.HostStateKind
	}{
		{"no history", nil, 0, testCfg, model.HostDown},
		{"always up", f(true, true, true), 0, testCfg, model.HostUp},
		{"one miss", f(true, false), 1, testCfg, model.HostDown},
		{"one flip back up is not unstable yet", f(false, true), 0, testCfg, model.HostUp},
		{"two flips -> unstable", f(true, false, true), 0, testCfg, model.HostUnstable},
		{"unstable while down", f(true, false, true, false), 1, testCfg, model.HostUnstable},
		{"three misses -> inactive beats unstable", f(true, false, true, false, false, false), 3, testCfg, model.HostInactive},
		{"misses below threshold", f(true, true, false, false), 2, testCfg, model.HostDown},
		{"flips outside window are forgotten", f(true, false, true, true, true, true, true), 0, testCfg, model.HostUp},
		{"higher flip threshold", f(true, false, true), 0, Config{InactiveAfterMisses: 3, UnstableIfFlips: 3, Window: 5}, model.HostUp},
		{"zero thresholds disable rules", f(true, false, true, false), 9, Config{}, model.HostDown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.flips, tt.misses, tt.cfg); got != tt.want {
				t.Errorf("Classify = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestStep(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	a := ip("10.0.0.9")

	h := Step(nil, a, true, 1, t0, testCfg)
	if h.State != model.HostUp || h.Misses != 0 || !h.FirstSeen.Equal(t0) || len(h.Flips) != 1 {
		t.Fatalf("new host: %+v", h)
	}
	// Re-applying the same run is a no-op.
	if again := Step(&h, a, false, 1, t0.Add(time.Hour), testCfg); !reflect.DeepEqual(again, h) {
		t.Fatalf("same run applied twice changed state: %+v", again)
	}
	// Misses accumulate up to inactive; last_seen stays at the last up run.
	for i, want := range []model.HostStateKind{model.HostDown, model.HostDown, model.HostInactive} {
		h = Step(&h, a, false, int64(i+2), t0.Add(time.Duration(i+1)*time.Hour), testCfg)
		if h.State != want || h.Misses != i+1 {
			t.Fatalf("miss %d: state %s misses %d, want %s", i+1, h.State, h.Misses, want)
		}
	}
	if !h.LastSeen.Equal(t0) {
		t.Errorf("LastSeen moved on a miss: %v", h.LastSeen)
	}
	// Coming back resets misses. Window up,down,down,down,up holds two
	// transitions, so the host counts as unstable.
	h = Step(&h, a, true, 5, t0.Add(5*time.Hour), testCfg)
	if h.State != model.HostUnstable || h.Misses != 0 || !h.LastSeen.Equal(t0.Add(5*time.Hour)) {
		t.Fatalf("back up: %+v", h)
	}
	// History is trimmed to the window.
	for r := int64(6); r < 20; r++ {
		h = Step(&h, a, true, r, t0, testCfg)
	}
	if len(h.Flips) != testCfg.Window || h.Flips[len(h.Flips)-1].RunID != 19 {
		t.Errorf("flips not trimmed to window: %+v", h.Flips)
	}
	// The input state is not mutated.
	before := Step(nil, a, true, 1, t0, testCfg)
	snapshot := append([]model.Flip(nil), before.Flips...)
	_ = Step(&before, a, false, 2, t0, testCfg)
	if !reflect.DeepEqual(before.Flips, snapshot) {
		t.Errorf("Step mutated its input")
	}
}

func TestAdvance(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	known := []model.HostState{
		Step(nil, ip("10.0.0.1"), true, 1, t0, testCfg),
		Step(nil, ip("10.0.0.2"), true, 1, t0, testCfg),
		Step(nil, ip("10.0.0.3"), true, 1, t0, testCfg),
	}
	obs := []model.HostObs{
		{RunID: 2, IP: ip("10.0.0.1"), Up: true},
		{RunID: 2, IP: ip("10.0.0.2"), Up: false}, // explicit down
		// 10.0.0.3 absent from obs: a miss
		{RunID: 2, IP: ip("10.0.0.7"), Up: false}, // never seen up: not tracked
	}
	// 10.0.0.8 only has a service (no host_obs row): it is up.
	curr := []model.ServiceObs{svc(2, "10.0.0.8", 80, "nginx", "")}
	got := Advance(known, obs, curr, 2, t0, testCfg)
	var states []string
	for _, h := range got {
		states = append(states, fmt.Sprintf("%s=%s/%d", h.IP, h.State, h.Misses))
	}
	want := []string{"10.0.0.1=up/0", "10.0.0.2=down/1", "10.0.0.3=down/1", "10.0.0.8=up/0"}
	if !reflect.DeepEqual(states, want) {
		t.Errorf("got %v, want %v", states, want)
	}
}

func TestHostChanges(t *testing.T) {
	t0 := time.Now()
	up1 := Step(nil, ip("10.0.0.1"), true, 1, t0, testCfg)
	tests := []struct {
		name string
		h    model.HostState
		run  int64
		want []string
	}{
		{"new host up", up1, 1, []string{`host_up 10.0.0.1 ""->"up"`}},
		{"stays up", Step(&up1, ip("10.0.0.1"), true, 2, t0, testCfg), 2, []string{}},
		{"goes down", Step(&up1, ip("10.0.0.1"), false, 2, t0, testCfg), 2, []string{`host_down 10.0.0.1 "up"->"down"`}},
		{"not observed in this run", up1, 2, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if g := fmtChanges(HostChanges([]model.HostState{tt.h}, tt.run, testCfg)); !reflect.DeepEqual(g, tt.want) {
				t.Errorf("got %q, want %q", g, tt.want)
			}
		})
	}
}

// TestThreeRunScenario drives run1 -> run2 -> run3 through Advance + Diff the
// same way ApplyRun does, and checks changes and host states per run.
func TestThreeRunScenario(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	type run struct {
		id       int64
		hosts    []string // hosts up in this run
		services []model.ServiceObs
	}
	runs := []run{
		{1, []string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			svc(1, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(1, "10.20.24.30", 23, "BusyBox telnetd", ""),
			svc(1, "10.20.24.30", 22, "OpenSSH", "7.4"),
			svc(1, "10.20.60.120", 80, "busybox httpd", ""),
		}},
		// run2: telnet gone, 8080 new, OpenSSH upgraded, flappy host disappears.
		{2, []string{"10.20.0.10", "10.20.24.30"}, []model.ServiceObs{
			svc(2, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(2, "10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			svc(2, "10.20.24.30", 22, "OpenSSH", "8.9p1"),
		}},
		// run3: flappy host reappears: up, down, up = 2 flips -> unstable.
		{3, []string{"10.20.0.10", "10.20.24.30", "10.20.60.120"}, []model.ServiceObs{
			svc(3, "10.20.0.10", 80, "nginx", "1.27.3"),
			svc(3, "10.20.0.10", 8080, "Werkzeug httpd", "3.0.1"),
			svc(3, "10.20.24.30", 22, "OpenSSH", "8.9p1"),
			svc(3, "10.20.60.120", 80, "busybox httpd", ""),
		}},
	}
	wantChanges := [][]string{
		nil, // baseline: ApplyRun records nothing
		{
			`new 10.20.0.10:8080/tcp ""->"Werkzeug httpd 3.0.1"`,
			`changed 10.20.24.30:22/tcp version "7.4"->"8.9p1"`,
			`gone 10.20.24.30:23/tcp "BusyBox telnetd"->""`,
			`host_down 10.20.60.120 "up"->"down"`,
			`gone 10.20.60.120:80/tcp "busybox httpd"->""`,
		},
		{
			`host_up 10.20.60.120 ""->"up"`,
			`unstable 10.20.60.120 flips ""->"2"`,
			`new 10.20.60.120:80/tcp ""->"busybox httpd"`,
		},
	}
	wantStates := []map[string]model.HostStateKind{
		{"10.20.0.10": model.HostUp, "10.20.24.30": model.HostUp, "10.20.60.120": model.HostUp},
		{"10.20.0.10": model.HostUp, "10.20.24.30": model.HostUp, "10.20.60.120": model.HostDown},
		{"10.20.0.10": model.HostUp, "10.20.24.30": model.HostUp, "10.20.60.120": model.HostUnstable},
	}

	var known []model.HostState
	var prev []model.ServiceObs
	for i, r := range runs {
		var obs []model.HostObs
		for _, h := range r.hosts {
			obs = append(obs, model.HostObs{RunID: r.id, IP: ip(h), Up: true})
		}
		known = Advance(known, obs, r.services, r.id, t0.Add(time.Duration(i)*time.Hour), testCfg)
		var got []model.Change
		if i > 0 {
			got = Diff(prev, r.services, known, testCfg)
			for _, c := range got {
				if c.RunID != r.id || c.PrevRunID != runs[i-1].id {
					t.Errorf("run %d: change %s has run %d prev %d", r.id, fmtChange(c), c.RunID, c.PrevRunID)
				}
			}
		}
		g := fmtChanges(got)
		w := wantChanges[i]
		if w == nil {
			w = []string{}
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("run %d changes:\n got  %q\n want %q", r.id, g, w)
		}
		states := map[string]model.HostStateKind{}
		for _, h := range known {
			states[h.IP.String()] = h.State
		}
		if !reflect.DeepEqual(states, wantStates[i]) {
			t.Errorf("run %d states: got %v, want %v", r.id, states, wantStates[i])
		}
		prev = r.services
	}

	// run4: flappy goes down again: still unstable and reported again;
	// then two more misses make it inactive.
	known = Advance(known, []model.HostObs{{RunID: 4, IP: ip("10.20.0.10"), Up: true}, {RunID: 4, IP: ip("10.20.24.30"), Up: true}},
		runs[2].services[:3], 4, t0, testCfg)
	g := fmtChanges(HostChanges(known, 4, testCfg))
	want := []string{`host_down 10.20.60.120 "up"->"down"`, `unstable 10.20.60.120 flips ""->"3"`}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("run4: got %q want %q", g, want)
	}
	for r := int64(5); r <= 6; r++ {
		known = Advance(known, nil, runs[2].services[:3], r, t0, testCfg)
	}
	for _, h := range known {
		if h.IP == ip("10.20.60.120") && (h.State != model.HostInactive || h.Misses != 3) {
			t.Errorf("after 3 misses: %+v", h)
		}
	}
}

func TestDiffRunIDsFromHistory(t *testing.T) {
	// Current run with no services at all: run IDs come from flips.
	h := Step(nil, ip("10.0.0.1"), true, 7, time.Now(), testCfg)
	h = Step(&h, ip("10.0.0.1"), false, 9, time.Now(), testCfg)
	got := Diff([]model.ServiceObs{svc(7, "10.0.0.1", 22, "OpenSSH", "")}, nil, []model.HostState{h}, testCfg)
	if len(got) != 2 {
		t.Fatalf("want host_down + gone, got %q", fmtChanges(got))
	}
	for _, c := range got {
		if c.RunID != 9 || c.PrevRunID != 7 {
			t.Errorf("run ids: %d/%d", c.RunID, c.PrevRunID)
		}
	}
}
