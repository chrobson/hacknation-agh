package diff

import (
	"net/netip"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestServiceInstability(t *testing.T) {
	cfg := Config{InactiveAfterMisses: 3, UnstableIfFlips: 2, Window: 5}
	ip := netip.MustParseAddr("127.0.0.1")
	flap := model.AssetKey{IP: ip, Port: 8787, Proto: "tcp"}
	once := model.AssetKey{IP: ip, Port: 15432, Proto: "tcp"}
	other := netip.MustParseAddr("10.20.60.120")
	hostFlap := model.AssetKey{IP: other, Port: 80, Proto: "tcp"}
	cs := []model.Change{
		{Kind: model.ChangeNew, Key: flap},
		{Kind: model.ChangeGone, Key: once},
		{Kind: model.ChangeChanged, Key: flap, Field: "version"},
		{Kind: model.ChangeUnstable, Key: model.AssetKey{IP: other}},
		{Kind: model.ChangeNew, Key: hostFlap},
	}
	prior := map[model.AssetKey]int{flap: 1, hostFlap: 3}
	got := ServiceInstability(cs, prior, cfg)
	if len(got) != 1 || got[0].Kind != model.ChangeUnstable || got[0].Key != flap || got[0].New != "2" || got[0].Field != "flips" {
		t.Fatalf("got %+v, want one unstable for 8787 with 2 flips", got)
	}
	if ServiceInstability(cs, prior, Config{}) != nil {
		t.Error("disabled threshold must yield nothing")
	}
	if PriorRuns(cfg) != 3 {
		t.Errorf("PriorRuns = %d", PriorRuns(cfg))
	}
}
