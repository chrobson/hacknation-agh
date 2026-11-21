package runner

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestBuildPlan(t *testing.T) {
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "app.lab.local":
			return []netip.Addr{netip.MustParseAddr("10.20.30.40"), netip.MustParseAddr("8.8.8.8")}, nil
		case "dup.lab.local":
			return []netip.Addr{netip.MustParseAddr("10.20.0.10")}, nil // inside 10.20.0.0/22
		}
		return nil, errors.New("nxdomain")
	}
	targets := []model.Target{
		{Kind: model.TargetCIDR, Value: "10.20.0.0/22"},
		{Kind: model.TargetCIDR, Value: "10.20.1.0/24"}, // contained, dropped
		{Kind: model.TargetIP, Value: "10.20.1.7"},      // contained, dropped
		{Kind: model.TargetIP, Value: "10.20.50.1"},
		{Kind: model.TargetCIDR, Value: "10.20.60.0/30"},
		{Kind: model.TargetIP, Value: "192.168.1.1"},  // outside allowlist
		{Kind: model.TargetCIDR, Value: "10.0.0.0/8"}, // larger than allowlist
		{Kind: model.TargetDomain, Value: "app.lab.local"},
		{Kind: model.TargetDomain, Value: "dup.lab.local"},
		{Kind: model.TargetDomain, Value: "missing.lab.local"},
		{Kind: model.TargetIP, Value: "not-an-ip"},
	}
	p := BuildPlan(context.Background(), targets, labAllow(), resolve, 0)
	var got []string
	for _, c := range p.Chunks {
		got = append(got, c.String())
	}
	want := "10.20.0.0/24 10.20.1.0/24 10.20.2.0/24 10.20.3.0/24 10.20.30.40/32 10.20.50.1/32 10.20.60.0/30"
	if g := strings.Join(got, " "); g != want {
		t.Errorf("chunks:\n got %s\nwant %s", g, want)
	}
	if p.Hostnames[netip.MustParseAddr("10.20.30.40")] != "app.lab.local" || p.Hostnames[netip.MustParseAddr("10.20.0.10")] != "dup.lab.local" {
		t.Errorf("hostnames = %v", p.Hostnames)
	}
	// 192.168.1.1, 10.0.0.0/8, 8.8.8.8 (from app.lab.local), missing domain, bad ip.
	if len(p.Skipped) != 5 {
		t.Errorf("skipped = %d: %v", len(p.Skipped), p.Skipped)
	}
}

func TestBuildPlanLabSize(t *testing.T) {
	p := BuildPlan(context.Background(), []model.Target{{Kind: model.TargetCIDR, Value: "10.20.0.0/18"}}, labAllow(), nil, 24)
	if len(p.Chunks) != 64 {
		t.Errorf("/18 -> %d chunks, want 64", len(p.Chunks))
	}
	p = BuildPlan(context.Background(), []model.Target{{Kind: model.TargetCIDR, Value: "10.20.0.0/18"}}, labAllow(), nil, 22)
	if len(p.Chunks) != 16 {
		t.Errorf("/18 by /22 -> %d chunks, want 16", len(p.Chunks))
	}
	p = BuildPlan(context.Background(), []model.Target{{Kind: model.TargetDomain, Value: "x"}}, labAllow(), nil, 24)
	if len(p.Chunks) != 0 || len(p.Skipped) != 1 {
		t.Errorf("domain without resolver: %+v", p)
	}
}
