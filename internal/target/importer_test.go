package target

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// fakeResolver answers from a fixed table; unknown names fail like NXDOMAIN.
type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ss, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out, nil
}

var testResolver = fakeResolver{
	"scanme.nmap.org": {"45.33.32.156", "2600:3c01::f03c:91ff:fe18:bb2f"},
	"app.lab.test":    {"10.20.1.20"},
	"mixed.lab.test":  {"10.20.1.21", "8.8.8.8"},
	"empty.lab.test":  {},
	"mapped.lab.test": {"::ffff:10.20.1.22"},
}

func testImporter() Importer {
	return Importer{
		Allow: NewAllowlist([]netip.Prefix{
			netip.MustParsePrefix("10.20.0.0/18"),
			netip.MustParsePrefix("192.0.2.0/24"),
		}),
		Resolver: testResolver,
	}
}

func TestCheckAllowlist(t *testing.T) {
	cases := []struct {
		in      string
		wantErr error
	}{
		{"10.20.0.0/24", nil},
		{"10.20.0.0/18", nil},
		{"10.20.63.255", nil},
		{"192.0.2.10", nil},
		{"app.lab.test", nil},
		{"mapped.lab.test", nil},
		{"10.20.64.0/24", ErrNotAllowed},
		{"10.0.0.0/8", ErrNotAllowed},
		{"8.8.8.8", ErrNotAllowed},
		{"::ffff:8.8.8.8", ErrNotAllowed},
		{"2001:db8::/64", ErrNotAllowed},
		{"scanme.nmap.org", ErrNotAllowed},
		{"mixed.lab.test", ErrNotAllowed}, // one resolved address outside
		{"empty.lab.test", ErrNoAddresses},
		{"nx.lab.test", nil},               // resolver error, checked below
		{"not a target", ErrInvalidTarget}, // spaces are not valid in a domain
	}
	im := testImporter()
	for _, c := range cases {
		_, err := im.Check(context.Background(), c.in)
		switch {
		case c.in == "nx.lab.test":
			if err == nil || !strings.HasPrefix(err.Error(), "resolve nx.lab.test") {
				t.Errorf("Check(%q) err = %v, want resolve error", c.in, err)
			}
		case c.in == "not a target":
			if err == nil {
				t.Errorf("Check(%q) must fail", c.in)
			}
		case !errors.Is(err, c.wantErr) && !(c.wantErr == nil && err == nil):
			t.Errorf("Check(%q) err = %v, want %v", c.in, err, c.wantErr)
		}
	}
	if _, err := (Importer{Resolver: testResolver}).Check(context.Background(), "10.20.0.1"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("empty allowlist must reject everything, got %v", err)
	}
}

func loadExpectedReport(t *testing.T) Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "import", "report.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestImportFixtures(t *testing.T) {
	want := loadExpectedReport(t)
	wantTargets := []model.Target{
		{Kind: model.TargetCIDR, Value: "10.20.0.0/24", Tags: []string{"lab", "web"}},
		{Kind: model.TargetIP, Value: "10.20.1.10", Tags: []string{"lab"}},
	}
	for _, name := range []string{"targets.csv", "targets.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "import", name))
			if err != nil {
				t.Fatal(err)
			}
			entries, err := ParseInput(DetectFormat(name, data), data)
			if err != nil {
				t.Fatal(err)
			}
			ts, rep := testImporter().Prepare(context.Background(), entries)
			rep.Finish(len(ts), len(ts)) // empty database: everything inserted
			if !reflect.DeepEqual(rep, want) {
				t.Errorf("report = %+v, want %+v", rep, want)
			}
			if !reflect.DeepEqual(ts, wantTargets) {
				t.Errorf("targets = %+v, want %+v", ts, wantTargets)
			}
			// The JSON encoding matches the example file byte for byte
			// (modulo whitespace).
			got, _ := json.Marshal(rep)
			exp, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "import", "report.example.json"))
			var cexp bytes.Buffer
			_ = json.Compact(&cexp, exp)
			if string(got) != cexp.String() {
				t.Errorf("json = %s, want %s", got, cexp.String())
			}
			// Content sniffing without the extension gives the same result.
			if f := DetectFormat("upload", data); f != DetectFormat(name, data) {
				t.Errorf("sniffed %s for %s", f, name)
			}
		})
	}
}

func TestPrepareDedupe(t *testing.T) {
	entries := []Entry{
		{Line: 1, Value: "10.20.0.0/24", Tags: []string{"a"}},
		{Line: 2, Value: "10.20.0.99/24", Tags: []string{"b"}}, // same after masking
		{Line: 3, Value: "10.20.1.10/32"},
		{Line: 4, Value: "10.20.1.10", Tags: []string{"c"}}, // same after collapse
		{Line: 5, Value: "APP.lab.test."},
		{Line: 6, Value: "app.lab.test"},
		{Line: 7, Value: "8.8.8.8"},
		{Line: 8, Value: "10.20.2.1", Err: errors.New("tags must be a list of strings")},
	}
	ts, rep := testImporter().Prepare(context.Background(), entries)
	if rep.Duplicates != 3 || len(ts) != 3 || len(rep.Errors) != 2 {
		t.Fatalf("ts=%+v rep=%+v", ts, rep)
	}
	if got := strings.Join(ts[0].Tags, ";"); got != "a;b" {
		t.Errorf("merged tags = %q", got)
	}
	if got := strings.Join(ts[1].Tags, ";"); got != "c" {
		t.Errorf("merged tags = %q", got)
	}
	if rep.Errors[0].Line != 7 || rep.Errors[0].Error != ErrNotAllowed.Error() {
		t.Errorf("error = %+v", rep.Errors[0])
	}
	// 2 of 3 already in the database.
	rep.Finish(len(ts), 1)
	if rep.Imported != 1 || rep.Duplicates != 5 {
		t.Errorf("after finish: %+v", rep)
	}
}

func TestResolvePrefixes(t *testing.T) {
	im := testImporter()
	ts := []model.Target{
		{Kind: model.TargetCIDR, Value: "10.20.0.0/24"},
		{Kind: model.TargetIP, Value: "10.20.1.20"},
		{Kind: model.TargetDomain, Value: "app.lab.test"}, // resolves to the IP above: deduped
		{Kind: model.TargetDomain, Value: "mapped.lab.test"},
	}
	got, err := im.ResolvePrefixes(context.Background(), ts)
	if err != nil {
		t.Fatal(err)
	}
	want := pfx("10.20.0.0/24", "10.20.1.20/32", "10.20.1.22/32")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	_, err = im.ResolvePrefixes(context.Background(), append(ts, model.Target{Kind: model.TargetDomain, Value: "scanme.nmap.org"}))
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("want ErrNotAllowed, got %v", err)
	}
}
