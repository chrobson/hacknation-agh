// Package scan runs host discovery and service detection (nmap). Owned by W1-2.
package scan

import (
	"context"
	"net/netip"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// Opts controls one scanner invocation.
type Opts struct {
	TopPorts   int  // phase 2 --top-ports
	MaxRate    int  // packets/s for THIS invocation (caller splits R/K)
	Privileged bool // -sS when true, -sT -Pn otherwise
}

// Scanner discovers live hosts and their services. Implementations MUST
// re-check every address against the allowlist right before exec.
type Scanner interface {
	// Discover returns live hosts in the given prefixes (phase 1, -sn).
	Discover(ctx context.Context, prefixes []netip.Prefix, o Opts) ([]netip.Addr, error)
	// Services returns open services with versions on live hosts (phase 2).
	Services(ctx context.Context, hosts []netip.Addr, o Opts) ([]model.ServiceObs, error)
}
