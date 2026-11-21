package target

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// Parse errors. They are reported verbatim in the import report.
var (
	ErrEmpty         = errors.New("empty value")
	ErrInvalidTarget = errors.New("not a valid IP address, CIDR or domain")
	ErrZone          = errors.New("IPv6 zones are not allowed")
	ErrInvalidDomain = errors.New("invalid domain name")
)

// Limits for a single tag and for tags per target.
const (
	MaxTagLen  = 64
	MaxTags    = 32
	maxDomain  = 253
	maxLabel   = 63
	maxValueSz = 512
)

// Parse classifies and normalizes one target value:
//
//   - IP addresses are unmapped (::ffff:a.b.c.d -> a.b.c.d) and printed canonically;
//   - CIDRs are masked (10.20.0.7/24 -> 10.20.0.0/24); a full-length prefix
//     (/32, /128) collapses to a plain IP so it dedupes with the bare address;
//   - domains are validated against RFC 1123 host name rules, lower-cased and
//     stripped of a trailing dot.
//
// The returned target has no ID and no tags.
func Parse(raw string) (model.Target, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return model.Target{}, ErrEmpty
	}
	if len(v) > maxValueSz {
		return model.Target{}, ErrInvalidTarget
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return model.Target{}, fmt.Errorf("%w: %s", ErrInvalidTarget, cleanErr(err))
		}
		if p.Addr().Zone() != "" {
			return model.Target{}, ErrZone
		}
		p = unmapPrefix(p).Masked()
		if p.IsSingleIP() {
			return model.Target{Kind: model.TargetIP, Value: p.Addr().String()}, nil
		}
		return model.Target{Kind: model.TargetCIDR, Value: p.String()}, nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		if a.Zone() != "" {
			return model.Target{}, ErrZone
		}
		return model.Target{Kind: model.TargetIP, Value: a.Unmap().String()}, nil
	}
	if looksNumeric(v) || strings.Contains(v, ":") {
		// "10.20.0.300" or a broken IPv6 literal: never treat it as a domain.
		return model.Target{}, ErrInvalidTarget
	}
	d, err := NormalizeDomain(v)
	if err != nil {
		return model.Target{}, err
	}
	return model.Target{Kind: model.TargetDomain, Value: d}, nil
}

// NormalizeDomain validates a host name per RFC 1123 (letters, digits and
// hyphens; labels 1-63 chars not starting or ending with a hyphen; at most
// 253 chars; at least two labels; the top-level label is not all-numeric)
// and returns it lower-cased without a trailing dot. The single exception to
// the two-label rule is "localhost" (services published on the scanning host).
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" {
		return "", ErrInvalidDomain
	}
	if len(d) > maxDomain {
		return "", fmt.Errorf("%w: longer than %d characters", ErrInvalidDomain, maxDomain)
	}
	if d == "localhost" {
		return d, nil
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: a fully qualified name is required", ErrInvalidDomain)
	}
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return "", fmt.Errorf("%w: %s", ErrInvalidDomain, err)
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: numeric top-level label", ErrInvalidDomain)
	}
	return d, nil
}

func checkLabel(l string) error {
	switch {
	case l == "":
		return errors.New("empty label")
	case len(l) > maxLabel:
		return fmt.Errorf("label longer than %d characters", maxLabel)
	case l[0] == '-' || l[len(l)-1] == '-':
		return fmt.Errorf("label %q starts or ends with a hyphen", l)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("label %q contains a forbidden character", l)
		}
	}
	return nil
}

// NormalizeTags trims, lower-cases and dedupes tags, dropping empty ones.
// Order of first occurrence is kept so exports are stable.
func NormalizeTags(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || slices.Contains(out, t) {
			continue
		}
		if len(t) > MaxTagLen {
			return nil, fmt.Errorf("tag longer than %d characters", MaxTagLen)
		}
		if strings.ContainsAny(t[:1], "=+-@") {
			// Would be read as a formula when the CSV export is opened in a
			// spreadsheet (CSV injection).
			return nil, fmt.Errorf("tag %q must not start with = + - @", t)
		}
		for _, r := range t {
			if r < 0x20 || r == 0x7f || r == ';' || r == ',' {
				return nil, fmt.Errorf("tag %q contains a forbidden character", t)
			}
		}
		out = append(out, t)
	}
	if len(out) > MaxTags {
		return nil, fmt.Errorf("more than %d tags", MaxTags)
	}
	return out, nil
}

// SplitTags splits a "a;b;c" tag list (CSV and form format).
func SplitTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ";")
}

// TargetPrefix returns the prefix of an IP or CIDR target. Domains have none.
func TargetPrefix(t model.Target) (netip.Prefix, bool) {
	switch t.Kind {
	case model.TargetIP:
		a, err := netip.ParseAddr(t.Value)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	case model.TargetCIDR:
		p, err := netip.ParsePrefix(t.Value)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	return netip.Prefix{}, false
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	a := p.Addr()
	if !a.Is4In6() {
		return p
	}
	bits := p.Bits() - 96
	if bits < 0 {
		// ::ffff:0:0/80 and similar cover more than IPv4; keep IPv6 form.
		return p
	}
	return netip.PrefixFrom(a.Unmap(), bits)
}

func looksNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// cleanErr strips the input echo from netip errors to keep reports short.
func cleanErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}
