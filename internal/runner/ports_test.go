package runner

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/store"
)

func TestEffectivePorts(t *testing.T) {
	cases := []struct {
		spec    string
		allowed []int
		want    string
		err     bool
	}{
		{"", nil, "[]", false},
		{"22,80", nil, "[22 80]", false},
		{"", []int{22, 443}, "[22 443]", false},
		{"22,80,443", []int{22, 443}, "[22 443]", false},
		{"80", []int{22, 443}, "", true},
		{"x", nil, "", true},
	}
	for _, c := range cases {
		got, err := EffectivePorts(c.spec, c.allowed)
		if c.err {
			if err == nil {
				t.Errorf("%q %v: expected error", c.spec, c.allowed)
			}
			continue
		}
		if err != nil || fmt.Sprint(got) != c.want {
			t.Errorf("%q %v: got %v %v want %s", c.spec, c.allowed, got, err, c.want)
		}
	}
}

func TestCountAddrs(t *testing.T) {
	ps := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("10.20.0.0/28")}
	if n := CountAddrs(ps); n != 18 {
		t.Errorf("CountAddrs = %d, want 18", n)
	}
	if n := CountAddrs([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}); n != 1<<62 {
		t.Errorf("huge prefix not saturated: %d", n)
	}
}

func TestResolvePorts(t *testing.T) {
	extra := []int{1883, 6379}
	cases := []struct {
		name    string
		cfg     store.ScanConfig
		addrs   uint64
		allowed []int
		want    string // profile ports(len or list) extra
		err     bool
	}{
		{"auto small -> all", store.ScanConfig{}, 1, nil, "all 65535 []", false},
		{"auto 16 -> all", store.ScanConfig{PortProfile: "auto"}, 16, nil, "all 65535 []", false},
		{"auto 17 -> top", store.ScanConfig{PortProfile: "auto", ExtraPorts: true}, 17, nil, "top 0 [1883 6379]", false},
		{"auto unknown size -> top", store.ScanConfig{}, 0, nil, "top 0 []", false},
		{"legacy list", store.ScanConfig{Ports: "22,80"}, 1, nil, "list [22 80] []", false},
		{"top + own extra", store.ScanConfig{PortProfile: "top", ExtraPorts: true, ExtraPortList: "8787,6379,15432"}, 1, nil,
			"top 0 [1883 6379 8787 15432]", false},
		{"top own extra only", store.ScanConfig{PortProfile: "top", ExtraPortList: "8787"}, 1, nil, "top 0 [8787]", false},
		{"top restricted", store.ScanConfig{PortProfile: "top", ExtraPorts: true}, 1, []int{22, 80}, "top [22 80] []", false},
		{"all restricted", store.ScanConfig{PortProfile: "all"}, 1000, []int{22}, "all [22] []", false},
		{"all big", store.ScanConfig{PortProfile: "all"}, 1 << 20, nil, "all 65535 []", false},
		{"list needs ports", store.ScanConfig{PortProfile: "list"}, 1, nil, "", true},
		{"bad extra", store.ScanConfig{PortProfile: "top", ExtraPortList: "x"}, 1, nil, "", true},
		{"bad profile", store.ScanConfig{PortProfile: "nope"}, 1, nil, "", true},
	}
	for _, c := range cases {
		pp, err := ResolvePorts(c.cfg, c.addrs, 16, c.allowed, extra)
		if c.err {
			if err == nil {
				t.Errorf("%s: expected error", c.name)
			}
			continue
		}
		ports := fmt.Sprint(pp.Ports)
		if len(pp.Ports) > 10 || len(pp.Ports) == 0 {
			ports = fmt.Sprint(len(pp.Ports))
		}
		got := fmt.Sprintf("%s %s %v", pp.Profile, ports, pp.Extra)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q %v, want %q", c.name, got, err, c.want)
		}
	}
}
