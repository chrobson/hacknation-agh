// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the process configuration. All values come from the environment
// (docker compose passes .env); defaults are safe for the local lab.
type Config struct {
	DatabaseURL  string         // ASI_DATABASE_URL
	HTTPAddr     string         // ASI_HTTP_ADDR, default :8080
	AllowedCIDRs []netip.Prefix // ASI_ALLOWED_CIDRS, comma separated; scanning outside is refused
	SecretKey    []byte         // ASI_SECRET_KEY, 32 bytes hex, AES-GCM key for the secrets table
	NmapPath     string         // ASI_NMAP_PATH, default "nmap"
	ScanPrivileged bool         // ASI_SCAN_PRIVILEGED: use -sS instead of -sT
	DojoURL      string         // ASI_DOJO_URL (empty = DefectDojo push disabled)
	DojoPush     bool           // ASI_DOJO_PUSH, default false (demo instance is public)
	Unstable     UnstableConfig
	TickEvery    time.Duration  // ASI_TICK_EVERY, scheduler tick, default 1m
}

// UnstableConfig defines host instability across runs.
type UnstableConfig struct {
	InactiveAfterMisses int // ASI_INACTIVE_AFTER_MISSES, default 3
	UnstableIfFlips     int // ASI_UNSTABLE_IF_FLIPS, default 2
	Window              int // ASI_UNSTABLE_WINDOW, default 5 runs
}

// DefaultAllowedCIDRs covers the docker lab and RFC 5737 TEST-NET-1.
const DefaultAllowedCIDRs = "10.20.0.0/18,192.0.2.0/24"

// Load reads the configuration from the environment.
func Load() (Config, error) {
	c := Config{
		DatabaseURL: env("ASI_DATABASE_URL", "postgres://asi:asi@localhost:5432/asi?sslmode=disable"),
		HTTPAddr:    env("ASI_HTTP_ADDR", ":8080"),
		NmapPath:    env("ASI_NMAP_PATH", "nmap"),
		DojoURL:     env("ASI_DOJO_URL", ""),
	}
	var err error
	if c.AllowedCIDRs, err = ParsePrefixes(env("ASI_ALLOWED_CIDRS", DefaultAllowedCIDRs)); err != nil {
		return c, fmt.Errorf("ASI_ALLOWED_CIDRS: %w", err)
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
