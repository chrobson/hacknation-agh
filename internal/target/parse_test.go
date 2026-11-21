package target

import (
	"errors"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		kind    model.TargetKind
		value   string
		wantErr error
	}{
		{"10.20.1.10", model.TargetIP, "10.20.1.10", nil},
		{"  10.20.1.10\t", model.TargetIP, "10.20.1.10", nil},
		{"::ffff:10.20.1.10", model.TargetIP, "10.20.1.10", nil},
		{"2001:DB8::1", model.TargetIP, "2001:db8::1", nil},
		{"10.20.0.0/24", model.TargetCIDR, "10.20.0.0/24", nil},
		{"10.20.0.77/24", model.TargetCIDR, "10.20.0.0/24", nil}, // masked
		{"10.20.1.10/32", model.TargetIP, "10.20.1.10", nil},     // collapses to IP
		{"::ffff:10.20.0.0/120", model.TargetCIDR, "10.20.0.0/24", nil},
		{"2001:db8::7/64", model.TargetCIDR, "2001:db8::/64", nil},
		{"Example.COM.", model.TargetDomain, "example.com", nil},
		{"scanme.nmap.org", model.TargetDomain, "scanme.nmap.org", nil},
		{"a-b.c1.lab", model.TargetDomain, "a-b.c1.lab", nil},
		{"xn--bcher-kva.example", model.TargetDomain, "xn--bcher-kva.example", nil},
		{"", "", "", ErrEmpty},
		{"   ", "", "", ErrEmpty},
		{"10.20.0.300", "", "", ErrInvalidTarget},
		{"10.20.0.0/33", "", "", ErrInvalidTarget},
		{"10.20.0.0/", "", "", ErrInvalidTarget},
		{"fe80::1%eth0", "", "", ErrZone},
		{"2001:db8::zz", "", "", ErrInvalidTarget},
		{"localhost", "", "", ErrInvalidDomain},
		{"foo_bar.com", "", "", ErrInvalidDomain},
		{"-foo.com", "", "", ErrInvalidDomain},
		{"foo-.com", "", "", ErrInvalidDomain},
		{"foo..com", "", "", ErrInvalidDomain},
		{"foo.123", "", "", ErrInvalidDomain},
		{"bücher.example", "", "", ErrInvalidDomain},
		{"http://example.com", "", "", ErrInvalidTarget},
		{strings.Repeat("a", 64) + ".com", "", "", ErrInvalidDomain},
		{strings.Repeat("abcdefghi.", 26) + "com", "", "", ErrInvalidDomain}, // 263 chars
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr != nil {
			if !errors.Is(err, c.wantErr) {
				t.Errorf("Parse(%q) err = %v, want %v", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) unexpected error %v", c.in, err)
			continue
		}
		if got.Kind != c.kind || got.Value != c.value {
			t.Errorf("Parse(%q) = %s %q, want %s %q", c.in, got.Kind, got.Value, c.kind, c.value)
		}
	}
}

func TestNormalizeTags(t *testing.T) {
	got, err := NormalizeTags([]string{" Lab", "web", "", "lab", "WEB "})
	if err != nil || strings.Join(got, ";") != "lab;web" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := NormalizeTags([]string{strings.Repeat("x", MaxTagLen+1)}); err == nil {
		t.Error("over-long tag must fail")
	}
	if _, err := NormalizeTags([]string{"a\nb"}); err == nil {
		t.Error("control characters must fail")
	}
}
