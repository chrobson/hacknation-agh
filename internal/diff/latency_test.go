package diff

import (
	"net/netip"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestLatencyChanged(t *testing.T) {
	cases := []struct {
		old, new int
		want     bool
	}{
		{40, 45, false},     // jitter
		{40, 300, false},    // 7x but only +260 ms
		{40, 590, true},     // Toxiproxy latency 500 ms on a fast service
		{590, 40, true},     // toxic removed
		{800, 1300, false},  // +500 ms but less than 2x
		{800, 1700, true},   // more than doubled and > 300 ms
		{2000, 2900, false}, // slow service, noisy
		{0, 900, false},     // not measured before
		{900, 0, false},     // not measured now
	}
	for _, c := range cases {
		if got := LatencyChanged(c.old, c.new); got != c.want {
			t.Errorf("LatencyChanged(%d, %d) = %v, want %v", c.old, c.new, got, c.want)
		}
	}
}

func TestLatencyChanges(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	mk := func(id int64, run int64, port uint16) model.ServiceObs {
		return model.ServiceObs{ID: id, RunID: run, Key: model.AssetKey{IP: ip, Port: port, Proto: "tcp"}}
	}
	prev := []model.ServiceObs{mk(1, 1, 8080), mk(2, 1, 8085), mk(3, 1, 8888), mk(4, 1, 15432)}
	curr := []model.ServiceObs{mk(11, 2, 8080), mk(12, 2, 8085), mk(13, 2, 8888), mk(15, 2, 3001)}
	ms := map[int64]int{
		1: 35, 11: 41, // unchanged
		2: 30, 12: 1050, // wordpress behind toxiproxy with latency
		3:  20, // 8888 not measured in the current run
		15: 25,
	}
	got := LatencyChanges(prev, curr, ms)
	if len(got) != 1 {
		t.Fatalf("got %d changes: %+v", len(got), got)
	}
	c := got[0]
	if c.Kind != model.ChangeChanged || c.Field != LatencyField || c.Key.Port != 8085 || c.Old != "30 ms" || c.New != "1050 ms" {
		t.Fatalf("unexpected change %+v", c)
	}
	if LatencyChanges(prev, curr, nil) != nil {
		t.Fatal("no timings: want no changes")
	}

	// Sorted after the nmap field changes of the same service.
	all := append([]model.Change{c}, model.Change{Kind: model.ChangeChanged, Key: c.Key, Field: "version", Old: "1", New: "2"})
	SortChanges(all)
	if all[0].Field != "version" || all[1].Field != LatencyField {
		t.Fatalf("order: %+v", all)
	}
}
