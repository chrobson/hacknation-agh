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
	// ExtraPorts are scanned in a second phase-2 pass on the same live hosts
	// (nmap cannot combine --top-ports with an explicit -p list): services
	// commonly exposed outside the top 1000 (MQTT, Redis, Memcached, NATS...).
	ExtraPorts []int
	// Ports, when set, is the explicit TCP port list of phase 2: it replaces
	// --top-ports and disables the ExtraPorts pass.
	Ports []int
	// DeepUnknown adds a pass with --version-intensity DeepIntensity over
	// the open ports the light pass could not name (at most MaxDeepPorts
	// per address family). Meant for small targets: nmap sends every probe
	// to each such port, which costs about a minute.
	DeepUnknown bool
}

// DeepIntensity is the nmap --version-intensity of the DeepUnknown pass:
// the lowest level that sends the probes naming PostgreSQL, MySQL and
// similar services on non-standard ports.
const DeepIntensity = 4

// MaxDeepPorts caps the ports of one DeepUnknown pass (see DeepPorts).
const MaxDeepPorts = 32

// DefaultExtraPorts are TCP ports outside nmap's top 1000 that commonly host
// exposed infrastructure services.
var DefaultExtraPorts = []int{1883, 2375, 2376, 4222, 5601, 5672, 6222, 6379, 8086, 8161, 8883,
	9042, 9093, 9200, 9300, 10250, 11211, 15672, 27017, 33060, 50070, 61616}

// Scanner discovers live hosts and their services. Implementations MUST
// re-check every address against the allowlist right before exec.
type Scanner interface {
	// Discover returns live hosts in the given prefixes (phase 1, -sn).
	Discover(ctx context.Context, prefixes []netip.Prefix, o Opts) ([]netip.Addr, error)
	// Services returns open services with versions on live hosts (phase 2).
	Services(ctx context.Context, hosts []netip.Addr, o Opts) ([]model.ServiceObs, error)
}
