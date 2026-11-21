// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is the process configuration. All values come from the environment
// (docker compose passes .env); defaults are safe for the local lab.
type Config struct {
	DatabaseURL    string         // ASI_DATABASE_URL
	HTTPAddr       string         // ASI_HTTP_ADDR, default :8080
	AllowedCIDRs   []netip.Prefix // ASI_ALLOWED_CIDRS, comma separated; scanning outside is refused
	SecretKey      []byte         // ASI_SECRET_KEY, 32 bytes hex, AES-GCM key for the secrets table
	NmapPath       string         // ASI_NMAP_PATH, default "nmap"
	ScanPrivileged bool           // ASI_SCAN_PRIVILEGED: use -sS instead of -sT
	DojoURL        string         // ASI_DOJO_URL (empty = DefectDojo push disabled)
	DojoPush       bool           // ASI_DOJO_PUSH, default false (demo instance is public)
	DojoToken      string         // ASI_DOJO_TOKEN, API v2 token (preferred over user/password)
	DojoUser       string         // ASI_DOJO_USER, used to obtain a token when DojoToken is empty
	DojoPassword   string         // ASI_DOJO_PASSWORD
	ScanExclude    []netip.Addr   // ASI_SCAN_EXCLUDE, comma separated addresses never scanned
	MaxRate        int            // ASI_MAX_RATE, upper bound of a scan config's packets/s, default 5000
	ScanPorts      []int          // ASI_SCAN_PORTS, allowed TCP ports ("22,80,8000-8100"); empty = no restriction
	Unstable       UnstableConfig
	TickEvery      time.Duration // ASI_TICK_EVERY, scheduler tick, default 1m
	HTTPTimeout    time.Duration // ASI_HTTP_TIMEOUT, per-request timeout of HTTP fingerprinting, default 10s
	HTTPRetries    int           // ASI_HTTP_RETRIES, retries after a timeout or dropped connection, default 1 (0 = none)
}

// UnstableConfig defines host instability across runs.
type UnstableConfig struct {
	InactiveAfterMisses int // ASI_INACTIVE_AFTER_MISSES, default 3
	UnstableIfFlips     int // ASI_UNSTABLE_IF_FLIPS, default 2
	Window              int // ASI_UNSTABLE_WINDOW, default 5 runs
}

// DefaultAllowedCIDRs covers the docker lab and RFC 5737 TEST-NET-1.
const DefaultAllowedCIDRs = "10.20.0.0/18,192.0.2.0/24"

// DefaultScanExclude lists lab infrastructure that answers ARP but is not a
// target: the network address, the docker bridge gateway and the scanner.
const DefaultScanExclude = "10.20.0.0,10.20.0.1,10.20.63.250"

// DefaultMaxRate caps the packets/s of one scan run (all workers together).
const DefaultMaxRate = 5000

// ParsePorts parses a TCP port list such as "22,80,443,8000-8100" into a
// sorted list without duplicates. An empty string gives nil.
func ParsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 1 || a > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		for p := a; p <= b; p++ {
			add(p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// FormatPorts is the inverse of ParsePorts for a sorted list: "22,80,8000-8100".
func FormatPorts(ps []int) string {
	var b strings.Builder
	for i := 0; i < len(ps); {
		j := i
		for j+1 < len(ps) && ps[j+1] == ps[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(ps[i]))
		if j > i {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(ps[j]))
		}
		i = j + 1
	}
	return b.String()
}

// Load reads the configuration from the environment.
func Load() (Config, error) {
	c := Config{
		DatabaseURL:  env("ASI_DATABASE_URL", "postgres://asi:asi@localhost:5432/asi?sslmode=disable"),
		HTTPAddr:     env("ASI_HTTP_ADDR", ":8080"),
		NmapPath:     env("ASI_NMAP_PATH", "nmap"),
		DojoURL:      env("ASI_DOJO_URL", ""),
		DojoToken:    os.Getenv("ASI_DOJO_TOKEN"),
		DojoUser:     os.Getenv("ASI_DOJO_USER"),
		DojoPassword: os.Getenv("ASI_DOJO_PASSWORD"),
	}
	var err error
	if c.AllowedCIDRs, err = ParsePrefixes(env("ASI_ALLOWED_CIDRS", DefaultAllowedCIDRs)); err != nil {
		return c, fmt.Errorf("ASI_ALLOWED_CIDRS: %w", err)
	}
	if c.ScanExclude, err = ParseAddrs(env("ASI_SCAN_EXCLUDE", DefaultScanExclude)); err != nil {
		return c, fmt.Errorf("ASI_SCAN_EXCLUDE: %w", err)
	}
	if c.MaxRate, err = envInt("ASI_MAX_RATE", DefaultMaxRate); err != nil {
		return c, err
	}
	if c.MaxRate < 1 {
		return c, fmt.Errorf("ASI_MAX_RATE must be at least 1")
	}
	if c.ScanPorts, err = ParsePorts(os.Getenv("ASI_SCAN_PORTS")); err != nil {
		return c, fmt.Errorf("ASI_SCAN_PORTS: %w", err)
	}
	if c.ScanPrivileged, err = envBool("ASI_SCAN_PRIVILEGED", false); err != nil {
		return c, err
	}
	if c.DojoPush, err = envBool("ASI_DOJO_PUSH", false); err != nil {
		return c, err
	}
	if c.Unstable.InactiveAfterMisses, err = envInt("ASI_INACTIVE_AFTER_MISSES", 3); err != nil {
		return c, err
	}
	if c.Unstable.UnstableIfFlips, err = envInt("ASI_UNSTABLE_IF_FLIPS", 2); err != nil {
		return c, err
	}
	if c.Unstable.Window, err = envInt("ASI_UNSTABLE_WINDOW", 5); err != nil {
		return c, err
	}
	if c.TickEvery, err = time.ParseDuration(env("ASI_TICK_EVERY", "1m")); err != nil {
		return c, fmt.Errorf("ASI_TICK_EVERY: %w", err)
	}
	if c.HTTPTimeout, err = time.ParseDuration(env("ASI_HTTP_TIMEOUT", "10s")); err != nil || c.HTTPTimeout <= 0 {
		return c, fmt.Errorf("ASI_HTTP_TIMEOUT: must be a positive duration such as 10s")
	}
	if c.HTTPRetries, err = envInt("ASI_HTTP_RETRIES", 1); err != nil {
		return c, err
	}
	if c.HTTPRetries < 0 || c.HTTPRetries > 3 {
		return c, fmt.Errorf("ASI_HTTP_RETRIES must be 0-3")
	}
	if k := os.Getenv("ASI_SECRET_KEY"); k != "" {
		if c.SecretKey, err = parseHexKey(k); err != nil {
			return c, fmt.Errorf("ASI_SECRET_KEY: %w", err)
		}
	}
	return c, nil
}

// ParsePrefixes parses a comma separated list of CIDRs or single IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// ParseAddrs parses a comma separated list of IP addresses.
func ParseAddrs(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

func envBool(k string, def bool) (bool, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", k, err)
	}
	return b, nil
}

func parseHexKey(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("want 64 hex chars (32 bytes), got %d", len(s))
	}
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		n, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(n)
	}
	return b, nil
}
