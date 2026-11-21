package scan

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/target"
)

type fakeExec struct {
	calls [][]string
	out   []byte
	err   error
}

func (f *fakeExec) run(_ context.Context, _ string, args []string) ([]byte, error) {
	f.calls = append(f.calls, args)
	return f.out, f.err
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func labAllow() target.Allowlist {
	return target.NewAllowlist([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18"), netip.MustParsePrefix("192.0.2.0/24")})
}

func TestDiscoveryArgs(t *testing.T) {
	got := DiscoveryArgs(
		[]netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.20.1.5/32")},
		Opts{MaxRate: 250},
		[]netip.Addr{netip.MustParseAddr("10.20.63.250")},
	)
	want := "-sn -n -PE -PS21,22,23,25,53,80,110,143,443,445,1883,3306,3389,5432,8080,8443 -PA80,443 " +
		"--max-rate 250 --exclude 10.20.63.250 -oX - 10.20.0.0/24 10.20.1.5"
	if g := strings.Join(got, " "); g != want {
		t.Errorf("args:\n got %s\nwant %s", g, want)
	}
}

func TestServiceArgs(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("10.20.0.11")}
	unpriv := strings.Join(ServiceArgs(hosts, Opts{TopPorts: 100, MaxRate: 50}), " ")
	if want := "-sT -Pn -n --top-ports 100 -sV --version-light --open --max-rate 50 -oX - 10.20.0.10 10.20.0.11"; unpriv != want {
		t.Errorf("unprivileged:\n got %s\nwant %s", unpriv, want)
	}
	priv := ServiceArgs(hosts, Opts{Privileged: true})
	if priv[0] != "-sS" || !slices.Contains(priv, "1000") || slices.Contains(priv, "--max-rate") {
		t.Errorf("privileged defaults: %v", priv)
	}
}

func TestDiscoverFiltersAndAllowlist(t *testing.T) {
	fe := &fakeExec{out: fixture(t, "run1_discovery.xml")}
	scanner := NewNmap("nmap", labAllow(), netip.MustParseAddr("10.20.63.250"))
	scanner.Exec = fe.run
	hosts, err := scanner.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/22")}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if !netip.MustParsePrefix("10.20.0.0/22").Contains(h) {
			t.Errorf("host %s outside requested prefix", h)
		}
	}
	if !slices.Contains(hosts, netip.MustParseAddr("10.20.0.10")) {
		t.Errorf("10.20.0.10 missing: %v", hosts)
	}
	if len(fe.calls) != 1 {
		t.Fatalf("calls = %d", len(fe.calls))
	}

	// A prefix outside the allowlist never reaches exec.
	fe.calls = nil
	_, err = scanner.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, Opts{})
	if !errors.Is(err, target.ErrNotAllowed) {
		t.Errorf("err = %v, want ErrNotAllowed", err)
	}
	_, err = scanner.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}, Opts{})
	if !errors.Is(err, target.ErrNotAllowed) {
		t.Errorf("err = %v, want ErrNotAllowed", err)
	}
	if len(fe.calls) != 0 {
		t.Errorf("exec called for disallowed targets: %v", fe.calls)
	}
}

func TestServicesAllowlistAndExclude(t *testing.T) {
	fe := &fakeExec{out: fixture(t, "run1_services.xml")}
	scanner := NewNmap("nmap", labAllow(), netip.MustParseAddr("10.20.63.250"))
	scanner.Exec = fe.run

	if _, err := scanner.Services(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("1.1.1.1")}, Opts{}); !errors.Is(err, target.ErrNotAllowed) {
		t.Errorf("err = %v, want ErrNotAllowed", err)
	}
	if len(fe.calls) != 0 {
		t.Fatal("exec called with a disallowed host")
	}
	// Only the scanner itself: nothing to do.
	svcs, err := scanner.Services(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.63.250")}, Opts{})
	if err != nil || svcs != nil || len(fe.calls) != 0 {
		t.Errorf("excluded only: svcs=%v err=%v calls=%d", svcs, err, len(fe.calls))
	}
	svcs, err = scanner.Services(context.Background(), []netip.Addr{netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("10.20.0.11")}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture covers 27 hosts; results are restricted to the requested ones.
	if len(svcs) != 3 {
		t.Errorf("services = %d (%v), want 3 (10.20.0.10:80, 10.20.0.11:80/443)", len(svcs), svcs)
	}
}

func TestExecErrorPropagates(t *testing.T) {
	fe := &fakeExec{err: context.DeadlineExceeded}
	scanner := NewNmap("", labAllow())
	scanner.Exec = fe.run
	_, err := scanner.Discover(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Opts{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if scanner.Path != "nmap" {
		t.Errorf("default path = %q", scanner.Path)
	}
}

func TestRunBinaryInterrupted(t *testing.T) {
	// Uses a harmless local binary (not nmap) to check context handling.
	sleep, err := lookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = runBinary(ctx, sleep, []string{"5"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func lookPath(name string) (string, error) { return exec.LookPath(name) }

func TestMixedFamiliesRunSeparately(t *testing.T) {
	fe := &fakeExec{out: []byte(`<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`)}
	allow := target.NewAllowlist([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/18"), netip.MustParsePrefix("2001:db8::/64")})
	scanner := NewNmap("nmap", allow, netip.MustParseAddr("10.20.63.250"), netip.MustParseAddr("2001:db8::1"))
	scanner.Exec = fe.run
	_, err := scanner.Discover(context.Background(), []netip.Prefix{
		netip.MustParsePrefix("2001:db8::100/120"), netip.MustParsePrefix("10.20.0.0/24"),
	}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 2 {
		t.Fatalf("calls = %d, want one per family", len(fe.calls))
	}
	v4, v6 := strings.Join(fe.calls[0], " "), strings.Join(fe.calls[1], " ")
	if strings.Contains(v4, "-6") || strings.Contains(v4, "2001:db8") || !strings.Contains(v4, "--exclude 10.20.63.250 ") {
		t.Errorf("v4 call: %s", v4)
	}
	if !strings.Contains(v6, " -6 ") || strings.Contains(v6, "10.20.") || !strings.Contains(v6, "--exclude 2001:db8::1 ") {
		t.Errorf("v6 call: %s", v6)
	}

	fe.calls = nil
	if _, err := scanner.Services(context.Background(), []netip.Addr{
		netip.MustParseAddr("10.20.0.10"), netip.MustParseAddr("2001:db8::105"),
	}, Opts{}); err != nil {
		t.Fatal(err)
	}
	if len(fe.calls) != 2 || slices.Contains(fe.calls[0], "-6") || !slices.Contains(fe.calls[1], "-6") {
		t.Errorf("services calls: %v", fe.calls)
	}
}

func TestExtraServiceArgs(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.8.100")}
	got := strings.Join(ExtraServiceArgs(hosts, Opts{Privileged: true, MaxRate: 100, ExtraPorts: []int{1883, 6379}}), " ")
	want := "-sS -Pn -n -p 1883,6379 -sV --version-light --open --max-rate 100 -oX - 10.20.8.100"
	if got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestServiceArgsExplicitPorts(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("10.20.0.10")}
	got := strings.Join(ServiceArgs(hosts, Opts{TopPorts: 100, MaxRate: 50, Ports: []int{22, 80, 81, 82, 443}}), " ")
	if want := "-sT -Pn -n -p 22,80-82,443 -sV --version-light --open --max-rate 50 -oX - 10.20.0.10"; got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestServiceArgsAllPorts(t *testing.T) {
	all := make([]int, 65535)
	for i := range all {
		all[i] = i + 1
	}
	got := strings.Join(ServiceArgs([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, Opts{Ports: all}), " ")
	if !strings.Contains(got, " -p- ") || strings.Contains(got, "--top-ports") {
		t.Errorf("all ports: %s", got)
	}
	if IsAllPorts(all[1:]) || IsAllPorts([]int{1, 65535}) {
		t.Error("partial lists are not all ports")
	}
}
