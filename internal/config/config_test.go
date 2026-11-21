package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts(" 443,22, 8000-8002,22")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 443, 8000, 8001, 8002}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, bad := range []string{"0", "65536", "a", "10-5", "1-x"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
	if p, err := ParsePorts(""); err != nil || p != nil {
		t.Errorf("empty: %v %v", p, err)
	}
}

func TestDefaultAllowsLoopback(t *testing.T) {
	t.Setenv("ASI_ALLOWED_CIDRS", "")
	t.Setenv("ASI_ALLOW_HOSTS", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"127.0.0.0/8": false, "::1/128": false}
	for _, p := range c.AllowedCIDRs {
		if _, ok := want[p.String()]; ok {
			want[p.String()] = true
		}
	}
	for p, ok := range want {
		if !ok {
			t.Errorf("default allowlist misses %s: %v", p, c.AllowedCIDRs)
		}
	}
	if c.AllPortsMaxAddrs != DefaultAllPortsMaxAddrs {
		t.Errorf("AllPortsMaxAddrs = %d", c.AllPortsMaxAddrs)
	}
}

func TestAllowHosts(t *testing.T) {
	old := HostResolver
	t.Cleanup(func() { HostResolver = old })
	HostResolver = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "host.docker.internal":
			return []netip.Addr{netip.MustParseAddr("192.168.65.254"), netip.MustParseAddr("::ffff:192.168.65.254")}, nil
		}
		return nil, errors.New("no such host")
	}
	t.Setenv("ASI_ALLOWED_CIDRS", "127.0.0.0/8")
	t.Setenv("ASI_ALLOW_HOSTS", " host.docker.internal ")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(c.AllowedCIDRs); got != "[127.0.0.0/8 192.168.65.254/32]" {
		t.Errorf("AllowedCIDRs = %s", got)
	}
	if fmt.Sprint(c.AllowHosts) != "[host.docker.internal]" {
		t.Errorf("AllowHosts = %v", c.AllowHosts)
	}
	t.Setenv("ASI_ALLOW_HOSTS", "nope.invalid")
	if _, err := Load(); err == nil {
		t.Error("unresolvable ASI_ALLOW_HOSTS must fail")
	}
}
