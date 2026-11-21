package target

import (
	"math"
	"math/bits"
	"net/netip"
	"sync"
	"time"
)

// Chunk sizing defaults (addresses per chunk).
const (
	DefaultInitialChunk = 256 // a /24 before any timing is known
	MinChunk            = 64
	MaxChunk            = 4096
	DefaultChunkTarget  = 90 * time.Second
	DefaultEWMAAlpha    = 0.3
)

// AddrCount returns the number of addresses in p, saturating at MaxUint64.
func AddrCount(p netip.Prefix) uint64 {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 64 {
		return math.MaxUint64
	}
	return 1 << host
}

// floorPow2 returns the largest power of two <= n (n >= 1).
func floorPow2(n int) int {
	if n < 1 {
		return 1
	}
	return 1 << (bits.Len(uint(n)) - 1)
}

// halves splits p into its two child prefixes. p must not be a single IP.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	a := p.Addr().As16()
	bit := p.Bits() // index of the first host bit
	if p.Addr().Is4() {
		bit += 96
	}
	a[bit/8] |= 0x80 >> (bit % 8)
	hiAddr := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		hiAddr = hiAddr.Unmap()
	}
	return lo, netip.PrefixFrom(hiAddr, p.Bits()+1)
}

// Cutter hands out consecutive chunks of a list of prefixes, each chunk a
// prefix of at most the requested size. Sizes may change between calls
// (adaptive sizing); oversized prefixes are split buddy-style on demand, so
// even a huge IPv6 range never materializes more than O(log n) pieces.
type Cutter struct {
	queue []netip.Prefix
}

// NewCutter queues the given prefixes (masked) in order.
func NewCutter(ps []netip.Prefix) *Cutter {
	q := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		q = append(q, p.Masked())
	}
	return &Cutter{queue: q}
}

// Next returns the next chunk with at most max(size,1) addresses (rounded
// down to a power of two) and false when everything has been handed out.
func (c *Cutter) Next(size int) (netip.Prefix, bool) {
	if len(c.queue) == 0 {
		return netip.Prefix{}, false
	}
	limit := uint64(floorPow2(size))
	for AddrCount(c.queue[0]) > limit {
		lo, hi := halves(c.queue[0])
		// Replace the head with its two halves, lower first.
		c.queue = append(c.queue, netip.Prefix{})
		copy(c.queue[2:], c.queue[1:])
		c.queue[0], c.queue[1] = lo, hi
	}
	p := c.queue[0]
	c.queue = c.queue[1:]
	return p, true
}

// Remaining reports whether more chunks are available.
func (c *Cutter) Remaining() bool { return len(c.queue) > 0 }

// Split cuts prefixes into fixed-size chunks (the initial, non-adaptive plan).
func Split(ps []netip.Prefix, size int) []netip.Prefix {
	c := NewCutter(ps)
	var out []netip.Prefix
	for {
		p, ok := c.Next(size)
		if !ok {
			return out
		}
		out = append(out, p)
	}
}

// Sizer picks the next chunk size so that one chunk takes roughly Target
// to scan. It keeps an EWMA of seconds per address over finished chunks and
// clamps the result to [Min, Max], rounded down to a power of two so it maps
// onto a CIDR. It is safe for concurrent use by runner workers.
type Sizer struct {
	Initial int           // size before the first observation
	Target  time.Duration // desired duration of one chunk
	Min     int
	Max     int
	Alpha   float64 // EWMA weight of the newest observation, (0,1]

	mu      sync.Mutex
	ewma    float64 // seconds per address
	samples int
}

// NewSizer returns a sizer with the default clamp (64..4096) and alpha.
// initial <= 0 means DefaultInitialChunk, target <= 0 means DefaultChunkTarget.
func NewSizer(initial int, target time.Duration) *Sizer {
	if initial <= 0 {
		initial = DefaultInitialChunk
	}
	if target <= 0 {
		target = DefaultChunkTarget
	}
	return &Sizer{Initial: initial, Target: target, Min: MinChunk, Max: MaxChunk, Alpha: DefaultEWMAAlpha}
}

// Observe feeds the measured duration of a finished chunk of addrs addresses.
func (s *Sizer) Observe(addrs int, d time.Duration) {
	if addrs <= 0 || d < 0 {
		return
	}
	spa := d.Seconds() / float64(addrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.samples == 0 {
		s.ewma = spa
	} else {
		a := s.Alpha
		if a <= 0 || a > 1 {
			a = DefaultEWMAAlpha
		}
		s.ewma = a*spa + (1-a)*s.ewma
	}
	s.samples++
}

// SecondsPerAddr returns the current EWMA (0 before any observation).
func (s *Sizer) SecondsPerAddr() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ewma
}

// Next returns the size (addresses) for the next chunk.
func (s *Sizer) Next() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	lo, hi := s.Min, s.Max
	if lo <= 0 {
		lo = MinChunk
	}
	if hi < lo {
		hi = lo
	}
	want := float64(s.Initial)
	if s.samples > 0 {
		if s.ewma <= 0 {
			want = float64(hi)
		} else {
			want = s.Target.Seconds() / s.ewma
		}
	}
	n := hi
	if want < float64(hi) {
		n = int(want)
	}
	if n < lo {
		n = lo
	}
	return floorPow2(n)
}
