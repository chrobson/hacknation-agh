//go:build lab

package scan

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/chrobson/hacknation-agh/internal/target"
)

// TestLabLive runs the real nmap scanner. It is compiled only with -tags lab
// and runs only inside the docker lab scanner container (scripts/scan-in-lab.sh
// sets ASI_LAB_SCAN=1). Never run it on the host.
func TestLabLive(t *testing.T) {
	if os.Getenv("ASI_LAB_SCAN") != "1" {
		t.Skip("ASI_LAB_SCAN!=1: live scan only inside the lab scanner container")
	}
	prefix := netip.MustParsePrefix(envOr("ASI_LAB_PREFIX", "10.20.0.0/24"))
	allow := target.NewAllowlist([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18")})
	n := NewNmap("nmap", allow,
		netip.MustParseAddr("10.20.63.250"), // scanner
		netip.MustParseAddr("10.20.0.1"),    // gateway
		netip.MustParseAddr("10.20.0.0"))    // network address answered by the bridge
	o := Opts{TopPorts: 100, MaxRate: 500, Privileged: os.Geteuid() == 0}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t0 := time.Now()
	hosts, err := n.Discover(ctx, []netip.Prefix{prefix}, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("phase 1: %d live hosts in %s (%s): %v", len(hosts), prefix, time.Since(t0).Round(time.Millisecond), hosts)
	if len(hosts) == 0 {
		t.Fatal("no live hosts")
	}
	t1 := time.Now()
	svcs, err := n.Services(ctx, hosts, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("phase 2: %d services (%s)", len(svcs), time.Since(t1).Round(time.Millisecond))
	for _, s := range svcs {
		t.Logf("  %s:%d/%s %q %q %q %s", s.Key.IP, s.Key.Port, s.Key.Proto, s.Banner, s.Product, s.Version, s.CPE)
	}
	if len(svcs) == 0 {
		t.Fatal("no services")
	}

	// Interruption: a tiny deadline must surface as a context error.
	short, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if _, err := n.Services(short, hosts, Opts{TopPorts: 1000, MaxRate: 10, Privileged: o.Privileged}); err == nil {
		t.Error("expected interruption error")
	} else {
		t.Logf("interrupted as expected: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
