package sig

import (
	"strings"
	"testing"
)

func TestSeverityOutdatedValidation(t *testing.T) {
	base := "id: x-test\nname: X\ncategory: other\nconfidence: 50\n"
	bad := map[string]string{
		"severity":             base + "severity: urgent\nmatchers:\n  - {type: title, regex: x}\n",
		"outdated-below":       base + "outdated: {below: latest, severity: high}\nmatchers:\n  - {type: title, regex: x}\n",
		"outdated-severity":    base + "outdated: {below: '6.0', severity: huge}\nmatchers:\n  - {type: title, regex: x}\n",
		"negate-path":          base + "matchers:\n  - {type: title, regex: x}\n  - {type: path, path: /a, status: [200], negate: true}\n",
		"negate-cookie":        base + "matchers:\n  - {type: cookie, name: sid, negate: true}\n",
		"version-only-nogroup": base + "matchers:\n  - {type: title, regex: x}\n  - {type: body, regex: 'v[0-9]', version_only: true}\n",
		"version-only-and":     base + "condition: and\nmatchers:\n  - {type: title, regex: x}\n  - {type: body, regex: 'v(?P<version>[0-9])', version_only: true}\n",
		"version-only-alone":   base + "matchers:\n  - {type: body, regex: 'v(?P<version>[0-9])', version_only: true}\n",
		"version-only-negated": base + "matchers:\n  - {type: title, regex: x}\n  - {type: body, regex: 'v(?P<version>[0-9])', version_only: true, negate: true}\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted:\n%s", name, y)
		}
	}
	ok := base + "severity: high\noutdated: {below: '6.0', severity: critical}\nmatchers:\n" +
		"  - {type: title, regex: x}\n  - {type: service, banner: auth, negate: true}\n" +
		"  - {type: path, path: /readme.html, status: [200], regex: 'Version (?P<version>[0-9.]+)', version_only: true}\n"
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"4.7", "6.0", -1, true},
		{"6.0", "6", 0, true},
		{"6.4.2", "6.0", 1, true},
		{"5.9.10", "5.10", -1, true},
		{"2.0.18-beta", "2.0.18", 0, true},
		{"9.6.0 or later", "10", -1, true},
		{"", "1.0", 0, false},
		{"latest", "1.0", 0, false},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d, %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
	if DojoSeverity("high") != "High" || DojoSeverity("") != "" {
		t.Error("DojoSeverity")
	}
}

func TestNegatedHTTPMatcherNeedsResponse(t *testing.T) {
	s, err := Parse([]byte("id: no-hsts\nname: No HSTS\ncategory: other\nconfidence: 50\nmatchers:\n  - {type: header, name: Strict-Transport-Security, negate: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]*Signature{s}, nil)
	if ds := e.Match(svc(6379, ""), httpObs(6379, "", "", nil)); len(ds) != 1 || !strings.HasPrefix(ds[0].Evidence["not:header"], "no match") {
		t.Fatalf("negated header on HTTP response: %+v", ds)
	}
	o := httpObs(6379, "", "", nil)
	o.Status = 0
	if ds := e.Match(svc(6379, ""), o); len(ds) != 0 {
		t.Fatalf("negated header matched without HTTP: %+v", ds)
	}
}
