package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
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

func TestHTTPTimeoutAndRetries(t *testing.T) {
	t.Setenv("ASI_HTTP_TIMEOUT", "")
	t.Setenv("ASI_HTTP_RETRIES", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPTimeout != 10*time.Second || c.HTTPRetries != 1 {
		t.Fatalf("defaults: %v, %d", c.HTTPTimeout, c.HTTPRetries)
	}
	t.Setenv("ASI_HTTP_TIMEOUT", "25s")
	t.Setenv("ASI_HTTP_RETRIES", "0")
	if c, err = Load(); err != nil || c.HTTPTimeout != 25*time.Second || c.HTTPRetries != 0 {
		t.Fatalf("custom: %v, %d, %v", c.HTTPTimeout, c.HTTPRetries, err)
	}
	for k, v := range map[string]string{"ASI_HTTP_TIMEOUT": "-1s", "ASI_HTTP_RETRIES": "9"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%s accepted", k, v)
			}
		})
	}
}

func TestDefaultHTTPAddr(t *testing.T) {
	t.Setenv("ASI_HTTP_ADDR", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":9080" || DefaultHTTPAddr != ":9080" {
		t.Fatalf("HTTPAddr = %q, want :9080", c.HTTPAddr)
	}
	t.Setenv("ASI_HTTP_ADDR", "127.0.0.1:7000")
	if c, err = Load(); err != nil || c.HTTPAddr != "127.0.0.1:7000" {
		t.Fatalf("override: %q, %v", c.HTTPAddr, err)
	}
}
