package scan

import (
	"context"
	"net/netip"
	"os/exec"
	"reflect"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/safety"
	"github.com/chrobson/hacknation-agh/internal/target"
)

func TestMeteredArgs(t *testing.T) {
	in := []string{"-sn", "-n", "--max-rate", "300", "-oX", "-", "10.20.0.0/24", "10.20.1.5"}
	want := []string{"-v", "-sn", "-n", "--max-rate", "300", "-oX", "/dev/fd/3", "10.20.0.0/24", "10.20.1.5"}
	if got := MeteredArgs(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	ops := TargetOperands(in)
	if len(ops) != 2 || ops[0].String() != "10.20.0.0/24" || ops[1].String() != "10.20.1.5/32" {
		t.Errorf("operands %v", ops)
	}
	if ops := TargetOperands(DiscoveryArgs([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{}, []netip.Addr{netip.MustParseAddr("10.20.0.1")})); len(ops) != 1 {
		t.Errorf("--exclude must not count as a target: %v", ops)
	}
}

func TestParseRawPackets(t *testing.T) {
	out := "Read data files from: /usr/share/nmap\nNmap done: 1 IP address (1 host up) scanned in 0.06 seconds\n           Raw packets sent: 3 (132B) | Rcvd: 6 (252B)\n"
	if n, ok := ParseRawPackets(out); !ok || n != 3 {
		t.Errorf("got %d %v", n, ok)
	}
	if _, ok := ParseRawPackets("Nmap done"); ok {
		t.Error("no counter expected")
	}
}

func TestEstimatePackets(t *testing.T) {
	if got := EstimatePackets(Stats{HostsTotal: 2, ScanType: "connect", NumServices: 100}, nil, 7, true); got != 207 {
		t.Errorf("connect = %d", got)
	}
	if got := EstimatePackets(Stats{HostsTotal: 2, ScanType: "syn", NumServices: 100}, nil, 150, true); got != 150 {
		t.Errorf("syn raw = %d", got)
	}
	if got := EstimatePackets(Stats{HostsTotal: 256}, []string{"-sn"}, 0, false); got != 256*19 {
		t.Errorf("-sn estimate = %d", got)
	}
}

// TestRealNmapLocalhost runs nmap against 127.0.0.1 only (never a network)
// when it is installed: the XML must still be parsed from fd 3 and the
// invocation recorded in the meter.
func TestRealNmapLocalhost(t *testing.T) {
	path, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap not installed")
	}
	lo := netip.MustParsePrefix("127.0.0.1/32")
	n := NewNmap(path, target.NewAllowlist([]netip.Prefix{lo}))
	m := safety.NewMeter()
	ctx := safety.WithMeter(context.Background(), m)
	if _, err := n.Services(ctx, []netip.Addr{lo.Addr()}, Opts{Ports: []int{1}, MaxRate: 50}); err != nil {
		t.Fatal(err)
	}
	r := m.Snapshot(target.NewAllowlist([]netip.Prefix{lo}))
	if r.NmapInvocations != 1 || r.TargetsChecked != 1 || r.TargetsOutsideAllowlist != 0 || r.NmapPackets < 1 {
		t.Errorf("receipt %+v", r)
	}
	if r.ArgvSample[0][:2] != "-v" {
		t.Errorf("argv %q", r.ArgvSample[0])
	}
}
