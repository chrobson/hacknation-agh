package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/safety"
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
		if o.DeepUnknown {
			if ports := DeepPorts(unknownPorts(out, group)); len(ports) > 0 {
				res, err := n.run(ctx, DeepServiceArgs(group, ports, o))
				if err != nil {
					return nil, err
				}
				named := map[model.AssetKey]model.ServiceObs{}
				for _, s := range res.Services {
					if want[s.Key.IP] && !unnamed(s) {
						named[s.Key] = s
					}
				}
				for i, s := range out {
					if d, ok := named[s.Key]; ok && unnamed(s) {
						out[i] = d
					}
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
		if IsAllPorts(o.Ports) {
			ports = []string{"-p-"}
		}
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

// IsAllPorts reports whether a sorted, duplicate-free port list is every TCP
// port (1-65535), which nmap spells -p-.
func IsAllPorts(ps []int) bool {
	return len(ps) == 65535 && ps[0] == 1 && ps[len(ps)-1] == 65535
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

// unnamed reports a service the version scan could not name.
func unnamed(s model.ServiceObs) bool {
	b := strings.TrimSuffix(s.Banner, "?")
	return s.Product == "" && (b == "" || b == "unknown" || b == "tcpwrapped")
}

// unknownPorts returns the sorted ports of unnamed services on the hosts of
// group.
func unknownPorts(svcs []model.ServiceObs, group []netip.Addr) []int {
	in := make(map[netip.Addr]bool, len(group))
	for _, h := range group {
		in[h.Unmap()] = true
	}
	set := map[int]bool{}
	for _, s := range svcs {
		if in[s.Key.IP.Unmap()] && s.Key.Proto == "tcp" && unnamed(s) {
			set[int(s.Key.Port)] = true
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// DeepPorts picks at most MaxDeepPorts of the unnamed ports for the deep
// version pass instead of skipping it when there are more. Ports that look
// like service ports come first; ports in the ephemeral range (49152+) and
// runs of four or more consecutive ports (e.g. FTP passive 21000-21010) are
// taken only while room is left. ports must be sorted; so is the result.
func DeepPorts(ports []int) []int {
	if len(ports) <= MaxDeepPorts {
		return ports
	}
	inRun := make([]bool, len(ports))
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j-i+1 >= 4 {
			for k := i; k <= j; k++ {
				inRun[k] = true
			}
		}
		i = j + 1
	}
	var first, rest []int
	for i, p := range ports {
		if p >= 49152 || inRun[i] {
			rest = append(rest, p)
		} else {
			first = append(first, p)
		}
	}
	out := append(first, rest...)
	out = out[:MaxDeepPorts]
	sort.Ints(out)
	return out
}

// DeepServiceArgs builds the DeepUnknown pass over ports.
func DeepServiceArgs(hosts []netip.Addr, ports []int, o Opts) []string {
	scanType := "-sT"
	if o.Privileged {
		scanType = "-sS"
	}
	args := []string{scanType, "-Pn", "-n", "-p", portList(ports), "-sV",
		"--version-intensity", strconv.Itoa(DeepIntensity), "--open"}
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
	start := time.Now()
	var (
		out  []byte
		raw  int64
		have bool
		err  error
		argv = args
	)
	if n.Exec != nil {
		out, err = n.Exec(ctx, n.Path, args)
	} else {
		argv = MeteredArgs(args)
		out, raw, have, err = runBinaryMetered(ctx, n.Path, argv)
	}
	if err != nil {
		return Result{}, err
	}
	res, err := Parse(bytes.NewReader(out))
	if err != nil {
		return res, err
	}
	if m := safety.From(ctx); m != nil {
		end := time.Now()
		elapsed := time.Duration(res.Stats.Elapsed * float64(time.Second))
		if elapsed <= 0 {
			elapsed = end.Sub(start)
		}
		m.AddNmap(safety.Invocation{
			Argv:    argv,
			Packets: EstimatePackets(res.Stats, args, raw, have),
			Raw:     have,
			Elapsed: elapsed,
			Start:   start,
			End:     end,
			Targets: TargetOperands(args),
		})
	}
	return res, nil
}

// MeteredArgs is the command line actually executed: -v makes nmap print
// its "Raw packets sent" counter on stdout, so the XML goes to file
// descriptor 3 instead of stdout. The builders keep "-oX -" so their output
// stays the documented command line.
func MeteredArgs(args []string) []string {
	out := make([]string, 0, len(args)+1)
	out = append(out, "-v")
	for i := 0; i < len(args); i++ {
		if args[i] == "-oX" && i+1 < len(args) && args[i+1] == "-" {
			out = append(out, "-oX", "/dev/fd/3")
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// discoveryProbes is the number of probes phase 1 sends per address
// (-PE, -PS list, -PA list).
func discoveryProbes() int64 {
	return int64(1 + len(DiscoveryPorts) + len(DiscoveryACKPorts))
}

// EstimatePackets returns the packets one invocation sent: nmap's raw
// packet counter when it printed one, plus one SYN per probed port of a
// connect scan (connect() packets are sent by the kernel and nmap does not
// count them). Without a counter, the probes are estimated from the XML
// (addresses x ports, or addresses x discovery probes for -sn).
func EstimatePackets(st Stats, args []string, raw int64, have bool) int64 {
	hosts := int64(st.HostsTotal)
	if st.ScanType == "connect" {
		return raw + hosts*int64(st.NumServices)
	}
	if have {
		return raw
	}
	if st.NumServices > 0 {
		return hosts * int64(st.NumServices)
	}
	for _, a := range args {
		if a == "-sn" {
			return hosts * discoveryProbes()
		}
	}
	return 0
}

// TargetOperands returns the target addresses and prefixes of a command
// line built by this package (the operands after "-oX -").
func TargetOperands(args []string) []netip.Prefix {
	var out []netip.Prefix
	for i := 0; i < len(args); i++ {
		if args[i] != "-oX" || i+1 >= len(args) {
			continue
		}
		for _, a := range args[i+2:] {
			if p, err := netip.ParsePrefix(a); err == nil {
				out = append(out, p.Masked())
			} else if ip, err := netip.ParseAddr(a); err == nil {
				ip = ip.Unmap()
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
		break
	}
	return out
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
	if err := runErr(ctx, err, stderr); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func runErr(ctx context.Context, err error, stderr *capped) error {
	if ctx.Err() != nil {
		return fmt.Errorf("nmap interrupted: %w", ctx.Err())
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("nmap exit %d: %s", ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return fmt.Errorf("nmap: %w", err)
	}
	return nil
}

// runBinaryMetered executes a MeteredArgs command line: the XML is read
// from file descriptor 3 (in memory, never on disk) and the end of stdout
// is searched for nmap's "Raw packets sent: N" line.
func runBinaryMetered(ctx context.Context, path string, args []string) ([]byte, int64, bool, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, 0, false, fmt.Errorf("nmap: pipe: %w", err)
	}
	defer pr.Close()
	cmd := exec.CommandContext(ctx, path, args...)
	stdout := &tail{max: 8192}
	stderr := &capped{max: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.ExtraFiles = []*os.File{pw}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		pw.Close()
		return nil, 0, false, fmt.Errorf("nmap: %w", err)
	}
	pw.Close()
	var xmlBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&xmlBuf, pr)
		close(done)
	}()
	werr := cmd.Wait()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		pr.Close()
		<-done
	}
	if err := runErr(ctx, werr, stderr); err != nil {
		return nil, 0, false, err
	}
	raw, ok := ParseRawPackets(stdout.String())
	return xmlBuf.Bytes(), raw, ok, nil
}

var rawPacketsRe = regexp.MustCompile(`Raw packets sent: (\d+)`)

// ParseRawPackets finds nmap's "Raw packets sent: N (...) | Rcvd: ..." line
// (printed under -v when raw packets were used).
func ParseRawPackets(stdout string) (int64, bool) {
	m := rawPacketsRe.FindAllStringSubmatch(stdout, -1)
	if len(m) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(m[len(m)-1][1], 10, 64)
	return n, err == nil
}

// tail is a writer keeping only the last max bytes.
type tail struct {
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.buf) }

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
