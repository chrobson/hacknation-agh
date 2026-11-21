package target

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func TestSplit(t *testing.T) {
	cases := []struct {
		name string
		in   []netip.Prefix
		size int
		want []string
	}{
		{"exact", pfx("10.20.0.0/24"), 256, []string{"10.20.0.0/24"}},
		{"smaller than chunk", pfx("10.20.1.10/32", "10.20.2.0/28"), 256, []string{"10.20.1.10/32", "10.20.2.0/28"}},
		{"quarters", pfx("10.20.0.0/24"), 64, []string{"10.20.0.0/26", "10.20.0.64/26", "10.20.0.128/26", "10.20.0.192/26"}},
		{"non power of two rounds down", pfx("10.20.0.0/24"), 100, []string{"10.20.0.0/26", "10.20.0.64/26", "10.20.0.128/26", "10.20.0.192/26"}},
		{"unmasked input", pfx("10.20.0.9/25"), 128, []string{"10.20.0.0/25"}},
		{"ipv6", pfx("2001:db8::/126"), 2, []string{"2001:db8::/127", "2001:db8::2/127"}},
	}
	for _, c := range cases {
		got := Split(c.in, c.size)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i].String() != c.want[i] {
				t.Errorf("%s: chunk %d = %s, want %s", c.name, i, got[i], c.want[i])
			}
		}
	}
}

func TestSplitLabCoversAllAddresses(t *testing.T) {
	chunks := Split(pfx("10.20.0.0/18"), DefaultInitialChunk)
	if len(chunks) != 64 {
		t.Fatalf("want 64 /24 chunks, got %d", len(chunks))
	}
	var total uint64
	next := netip.MustParseAddr("10.20.0.0")
	for _, c := range chunks {
		if c.Addr() != next {
			t.Fatalf("gap or overlap at %s (want start %s)", c, next)
		}
		total += AddrCount(c)
		next = c.Addr()
		for range AddrCount(c) {
			next = next.Next()
		}
	}
	if total != 16384 {
		t.Fatalf("total %d", total)
	}
}

func TestCutterAdaptiveSizes(t *testing.T) {
	c := NewCutter(pfx("10.20.0.0/22")) // 1024 addresses
	var got []string
	for _, size := range []int{256, 64, 64, 4096, 4096} {
		p, ok := c.Next(size)
		if !ok {
			break
		}
		got = append(got, p.String())
	}
	want := []string{"10.20.0.0/24", "10.20.1.0/26", "10.20.1.64/26", "10.20.1.128/25", "10.20.2.0/23"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if c.Remaining() {
		t.Fatal("cutter should be empty")
	}
	if _, ok := c.Next(64); ok {
		t.Fatal("Next on empty cutter must return false")
	}
}

func TestCutterHugeIPv6(t *testing.T) {
	c := NewCutter(pfx("2001:db8::/32"))
	p, ok := c.Next(4096)
	if !ok || p.String() != "2001:db8::/116" {
		t.Fatalf("got %v %v", p, ok)
	}
	if len(c.queue) > 128 {
		t.Fatalf("queue grew to %d", len(c.queue))
	}
}

func TestAddrCount(t *testing.T) {
	if n := AddrCount(netip.MustParsePrefix("10.20.0.0/18")); n != 16384 {
		t.Errorf("got %d", n)
	}
	if n := AddrCount(netip.MustParsePrefix("2001:db8::/32")); n != ^uint64(0) {
		t.Errorf("v6 should saturate, got %d", n)
	}
}

func TestSizer(t *testing.T) {
	cases := []struct {
		name string
		obs  [][2]float64 // addrs, seconds
		want int
	}{
		{"initial", nil, 256},
		{"fast network grows to max", [][2]float64{{256, 2}}, 4096},    // 90/(2/256)=11520 -> clamp 4096
		{"slow network shrinks to min", [][2]float64{{256, 1200}}, 64}, // 90/4.69=19 -> clamp 64
		{"target hit", [][2]float64{{256, 45}}, 512},                   // 90/(45/256)=512
		{"rounds down to pow2", [][2]float64{{256, 60}}, 256},          // 384 -> 256
		{"ewma smooths", [][2]float64{{256, 45}, {256, 90}}, 256},      // spa 0.1758 -> 0.2285 -> 393 -> 256
		{"zero duration", [][2]float64{{256, 0}}, 4096},
	}
	for _, c := range cases {
		s := NewSizer(0, 0)
		for _, o := range c.obs {
			s.Observe(int(o[0]), time.Duration(o[1]*float64(time.Second)))
		}
		if got := s.Next(); got != c.want {
			t.Errorf("%s: Next() = %d, want %d (spa=%f)", c.name, got, c.want, s.SecondsPerAddr())
		}
	}
	s := NewSizer(1000, 30*time.Second)
	if got := s.Next(); got != 512 {
		t.Errorf("custom initial 1000 should round to 512, got %d", got)
	}
}

func TestSizerConcurrent(t *testing.T) {
	s := NewSizer(0, 0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Observe(256, 45*time.Second)
				_ = s.Next()
			}
		}()
	}
	wg.Wait()
	if got := s.Next(); got != 512 {
		t.Fatalf("got %d", got)
	}
}
