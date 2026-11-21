package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/target"
)

// DiscoveryPorts are the TCP SYN ping ports used in phase 1 (-PS).
var DiscoveryPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1883, 3306, 3389, 5432, 8080, 8443}

// DiscoveryACKPorts are the TCP ACK ping ports used in phase 1 (-PA).
var DiscoveryACKPorts = []int{80, 443}

// DefaultTopPorts is used when Opts.TopPorts is not set.
const DefaultTopPorts = 1000

// ExecFunc runs a command and returns its stdout. It is a seam for tests:
// unit tests replace it so nmap is never executed on the host.
type ExecFunc func(ctx context.Context, path string, args []string) ([]byte, error)

// Nmap implements Scanner by executing the nmap binary with XML output on
// stdout. The XML is parsed in memory and never written to disk.
type Nmap struct {
	Path    string           // nmap binary, e.g. config.NmapPath
	Allow   target.Allowlist // re-checked right before every exec
	Exclude []netip.Addr     // addresses never scanned (scanner itself, gateway)
	Exec    ExecFunc         // nil = run the real binary
}

var _ Scanner = (*Nmap)(nil)

// NewNmap returns an nmap-backed Scanner.
func NewNmap(path string, allow target.Allowlist, exclude ...netip.Addr) *Nmap {
	if path == "" {
		path = "nmap"
	}
	return &Nmap{Path: path, Allow: allow, Exclude: exclude}
}

// Discover runs phase 1 host discovery (-sn) and returns live hosts.
func (n *Nmap) Discover(ctx context.Context, prefixes []netip.Prefix, o Opts) ([]netip.Addr, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	if err := n.Allow.CheckPrefixes(prefixes); err != nil {
		return nil, err
	}
	var out []netip.Addr
	// nmap cannot mix IPv4 and IPv6 targets in one invocation (-6).
	for _, group := range splitPrefixesByFamily(prefixes) {
		res, err := n.run(ctx, DiscoveryArgs(group, o, familyAddrs(n.Exclude, group[0].Addr().Is6())))
		if err != nil {
			return nil, err
		}
		for _, ip := range res.UpHosts() {
			if n.Allow.AllowsAddr(ip) && !n.excluded(ip) && inAny(ip, group) {
				out = append(out, ip)
			}
		}
	}
	sortAddrs(out)
	return out, nil
}

// Services runs phase 2 (port scan with light version detection) on hosts
// already known to be live.
func (n *Nmap) Services(ctx context.Context, hosts []netip.Addr, o Opts) ([]model.ServiceObs, error) {
	hosts = n.filterExcluded(hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	for _, h := range hosts {
		if !n.Allow.AllowsAddr(h) {
			return nil, fmt.Errorf("%w: %s", target.ErrNotAllowed, h)
		}
	}
	want := make(map[netip.Addr]bool, len(hosts))
	for _, h := range hosts {
		want[h.Unmap()] = true
	}
	var out []model.ServiceObs
	// nmap cannot mix IPv4 and IPv6 targets in one invocation (-6).
	for _, group := range splitAddrsByFamily(hosts) {
		res, err := n.run(ctx, ServiceArgs(group, o))
		if err != nil {
			return nil, err
		}
		seen := map[model.AssetKey]bool{}
		for _, s := range res.Services {
			if want[s.Key.IP] {
				out = append(out, s)
				seen[s.Key] = true
			}
		}
		if len(o.ExtraPorts) > 0 && len(o.Ports) == 0 {
			res, err := n.run(ctx, ExtraServiceArgs(group, o))
			if err != nil {
				return nil, err
			}
			for _, s := range res.Services {
				if want[s.Key.IP] && !seen[s.Key] {
					out = append(out, s)
					seen[s.Key] = true
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return keyLess(out[i].Key, out[j].Key) })
	return out, nil
}

// DiscoveryArgs builds the phase 1 command line (without the binary).
func DiscoveryArgs(prefixes []netip.Prefix, o Opts, exclude []netip.Addr) []string {
	args := []string{
		"-sn", "-n", "-PE",
		"-PS" + portList(DiscoveryPorts),
		"-PA" + portList(DiscoveryACKPorts),
	}
	args = appendRate(args, o.MaxRate)
	if len(exclude) > 0 {
		ex := make([]string, len(exclude))
		for i, a := range exclude {
			ex[i] = a.String()
		}
		args = append(args, "--exclude", strings.Join(ex, ","))
	}
	if len(prefixes) > 0 && prefixes[0].Addr().Unmap().Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-oX", "-")
	for _, p := range prefixes {
		p = p.Masked()
		if p.IsSingleIP() {
			args = append(args, p.Addr().String())
		} else {
			args = append(args, p.String())
		}
	}
	return args
}

// ServiceArgs builds the phase 2 command line (without the binary).
// Privileged uses a SYN scan; otherwise a connect scan. Both skip host
// discovery (-Pn) because the hosts come from phase 1.
func ServiceArgs(hosts []netip.Addr, o Opts) []string {
	scanType := "-sT"
	if o.Privileged {
		scanType = "-sS"
	}
	top := o.TopPorts
	if top <= 0 {
		top = DefaultTopPorts
	}
	ports := []string{"--top-ports", strconv.Itoa(top)}
	if len(o.Ports) > 0 {
		ports = []string{"-p", config.FormatPorts(o.Ports)}
	}
	args := []string{scanType, "-Pn", "-n"}
	args = append(args, ports...)
	args = append(args, "-sV", "--version-light", "--open")
	args = appendRate(args, o.MaxRate)
	if len(hosts) > 0 && hosts[0].Unmap().Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-oX", "-")
	for _, h := range hosts {
		args = append(args, h.Unmap().String())
	}
	return args
}

// ExtraServiceArgs builds the second phase-2 pass over o.ExtraPorts.
func ExtraServiceArgs(hosts []netip.Addr, o Opts) []string {
	scanType := "-sT"
	if o.Privileged {
		scanType = "-sS"
	}
	args := []string{scanType, "-Pn", "-n", "-p", portList(o.ExtraPorts), "-sV", "--version-light", "--open"}
	args = appendRate(args, o.MaxRate)
	if len(hosts) > 0 && hosts[0].Unmap().Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-oX", "-")
	for _, h := range hosts {
		args = append(args, h.Unmap().String())
	}
	return args
}

func appendRate(args []string, rate int) []string {
	if rate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(rate))
	}
	return args
}

func (n *Nmap) run(ctx context.Context, args []string) (Result, error) {
	fn := n.Exec
	if fn == nil {
		fn = runBinary
	}
	out, err := fn(ctx, n.Path, args)
	if err != nil {
		return Result{}, err
	}
	return Parse(bytes.NewReader(out))
}

func (n *Nmap) excluded(ip netip.Addr) bool {
	for _, e := range n.Exclude {
		if e.Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

func (n *Nmap) filterExcluded(hosts []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(hosts))
	for _, h := range hosts {
		if !n.excluded(h) {
			out = append(out, h.Unmap())
		}
	}
	return out
}

// splitPrefixesByFamily returns the IPv4 group then the IPv6 group (each
// only when non-empty).
func splitPrefixesByFamily(ps []netip.Prefix) [][]netip.Prefix {
	var v4, v6 []netip.Prefix
	for _, p := range ps {
		if p.Addr().Unmap().Is6() {
			v6 = append(v6, p)
		} else {
			v4 = append(v4, p)
		}
	}
	var out [][]netip.Prefix
	for _, g := range [][]netip.Prefix{v4, v6} {
		if len(g) > 0 {
			out = append(out, g)
		}
	}
	return out
}

func splitAddrsByFamily(as []netip.Addr) [][]netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range as {
		if a.Unmap().Is6() {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	var out [][]netip.Addr
	for _, g := range [][]netip.Addr{v4, v6} {
		if len(g) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// familyAddrs keeps the addresses of one family (for --exclude).
func familyAddrs(as []netip.Addr, v6 bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range as {
		if a.Unmap().Is6() == v6 {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func inAny(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// runBinary executes nmap, keeping stdout (the XML) in memory. A cancelled
// or expired context kills the process and the context error is returned so
// callers can tell an interruption from a scan failure.
func runBinary(ctx context.Context, path string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout bytes.Buffer
	stderr := &capped{max: 4096}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("nmap interrupted: %w", ctx.Err())
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("nmap exit %d: %s", ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("nmap: %w", err)
	}
	return stdout.Bytes(), nil
}

// capped is a writer keeping only the first max bytes.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *capped) String() string { return c.buf.String() }
