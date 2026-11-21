package target

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllowlist(t *testing.T) {
	al := NewAllowlist([]netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/18"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})
	cases := []struct {
		in   string
		want bool
	}{
		{"10.20.0.0/18", true},
		{"10.20.5.0/24", true},
		{"10.20.63.255/32", true},
		{"10.20.64.0/24", false}, // just outside the /18
		{"10.0.0.0/8", false},    // wider than the allowed prefix
		{"8.8.8.8/32", false},
		{"192.0.2.10/32", true},
	}
	for _, c := range cases {
		if got := al.AllowsPrefix(netip.MustParsePrefix(c.in)); got != c.want {
			t.Errorf("AllowsPrefix(%s) = %v, want %v", c.in, got, c.want)
		}
	}
	if al.AllowsAddr(netip.MustParseAddr("1.1.1.1")) {
		t.Error("1.1.1.1 must not be allowed")
	}
	if err := al.CheckPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("want ErrNotAllowed, got %v", err)
	}
	if NewAllowlist(nil).AllowsAddr(netip.MustParseAddr("10.20.0.1")) {
		t.Error("empty allowlist must allow nothing")
	}
}
