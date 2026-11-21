// Package target parses, validates and chunks scan targets.
package target

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrNotAllowed is returned when a target lies outside the allowlist.
var ErrNotAllowed = errors.New("target outside allowed networks")

// Allowlist restricts which networks may ever be scanned. It is enforced at
// import time (internal/target) and again right before exec (internal/scan).
type Allowlist struct {
	prefixes []netip.Prefix
}

// NewAllowlist builds an allowlist. An empty list allows nothing.
func NewAllowlist(p []netip.Prefix) Allowlist { return Allowlist{prefixes: p} }

// AllowsAddr reports whether a single address is inside the allowlist.
func (a Allowlist) AllowsAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowsPrefix reports whether the whole prefix lies inside one allowed prefix.
func (a Allowlist) AllowsPrefix(q netip.Prefix) bool {
	q = q.Masked()
	for _, p := range a.prefixes {
		if p.Bits() <= q.Bits() && p.Contains(q.Addr()) {
			return true
		}
	}
	return false
}

// CheckPrefixes returns ErrNotAllowed for the first prefix outside the list.
func (a Allowlist) CheckPrefixes(ps []netip.Prefix) error {
	for _, p := range ps {
		if !a.AllowsPrefix(p) {
			return fmt.Errorf("%w: %s", ErrNotAllowed, p)
		}
	}
	return nil
}
