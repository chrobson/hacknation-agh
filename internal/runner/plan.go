package runner

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/target"
)

// Default chunk sizes: an IPv4 chunk is at most a /24 (256 addresses).
// IPv6 prefixes shorter than MinIPv6Bits are refused (not enumerable).
const (
	DefaultChunkBits4 = 24
	MinIPv6Bits       = 120
)

// Resolver resolves a domain target to addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Plan is the expansion of targets into scan chunks.
type Plan struct {
	Chunks    []netip.Prefix        // disjoint, sorted
	Hostnames map[netip.Addr]string // addresses resolved from domain targets
	Skipped   []string              // "value: reason" for targets not scanned
}

// BuildPlan turns targets into disjoint chunks of at most /chunkBits4 (IPv4).
// Domains are resolved with resolve (nil = domains skipped). Every resulting
// prefix is checked against the allowlist; disallowed ones are skipped.
//
// The chunk size is fixed (default /24) because chunks are stored when the
// run is created and resumption works per chunk; see docs/ARCHITECTURE.md.
func BuildPlan(ctx context.Context, targets []model.Target, allow target.Allowlist, resolve Resolver, chunkBits4 int) Plan {
	if chunkBits4 <= 0 || chunkBits4 > 32 {
		chunkBits4 = DefaultChunkBits4
	}
	p := Plan{Hostnames: map[netip.Addr]string{}}
	var prefixes []netip.Prefix
	add := func(value string, q netip.Prefix) {
		q = q.Masked()
		switch {
		case q.Addr().Is6() && q.Bits() < MinIPv6Bits:
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: prefiks IPv6 krótszy niż /%d", value, MinIPv6Bits))
		case !allow.AllowsPrefix(q):
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: poza dozwolonymi sieciami", value))
		default:
			prefixes = append(prefixes, q)
		}
	}
	for _, t := range targets {
		v := strings.TrimSpace(t.Value)
		switch t.Kind {
		case model.TargetIP:
			a, err := netip.ParseAddr(v)
			if err != nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", v, err))
				continue
			}
			a = a.Unmap()
			add(v, netip.PrefixFrom(a, a.BitLen()))
		case model.TargetCIDR:
			q, err := netip.ParsePrefix(v)
			if err != nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", v, err))
				continue
			}
			add(v, q)
		case model.TargetDomain:
			if resolve == nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: brak resolwera DNS", v))
				continue
			}
			addrs, err := resolve(ctx, v)
			if err != nil || len(addrs) == 0 {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: nie rozwiązano nazwy (%v)", v, err))
				continue
			}
			for _, a := range addrs {
				a = a.Unmap()
				if _, ok := p.Hostnames[a]; !ok {
					p.Hostnames[a] = v
				}
				add(v, netip.PrefixFrom(a, a.BitLen()))
			}
		default:
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: nieznany typ %q", v, t.Kind))
		}
	}
	for _, q := range dedupe(prefixes) {
		p.Chunks = append(p.Chunks, split(q, chunkBits4)...)
	}
	return p
}

// dedupe sorts prefixes and drops those contained in another one.
func dedupe(ps []netip.Prefix) []netip.Prefix {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr() != ps[j].Addr() {
			return ps[i].Addr().Less(ps[j].Addr())
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var out []netip.Prefix
	for _, q := range ps {
		if n := len(out); n > 0 {
			last := out[n-1]
			if last.Addr().BitLen() == q.Addr().BitLen() && last.Bits() <= q.Bits() && last.Contains(q.Addr()) {
				continue
			}
		}
		out = append(out, q)
	}
	return out
}

// split cuts an IPv4 prefix into /bits pieces; smaller prefixes and IPv6
// are returned as is.
func split(q netip.Prefix, bits int) []netip.Prefix {
	if !q.Addr().Is4() || q.Bits() >= bits {
		return []netip.Prefix{q}
	}
	n := 1 << (bits - q.Bits())
	out := make([]netip.Prefix, 0, n)
	base := q.Addr().As4()
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	step := uint32(1) << (32 - bits)
	for i := 0; i < n; i++ {
		v := start + uint32(i)*step
		a := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		out = append(out, netip.PrefixFrom(a, bits))
	}
	return out
}
