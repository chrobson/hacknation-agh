package target

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/chrobson/hacknation-agh/internal/model"
)

func TestParseCSV(t *testing.T) {
	in := "value,tags\n10.20.0.0/24,lab;web\n\n# comment\n\"10.20.1.10\", lab ; x\nexample.lab,\n"
	got, err := ParseCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Line: 2, Value: "10.20.0.0/24", Tags: []string{"lab", "web"}},
		{Line: 5, Value: "10.20.1.10", Tags: []string{"lab ", " x"}},
		{Line: 6, Value: "example.lab"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	// No header: first row is data.
	got, err = ParseCSV(strings.NewReader("10.20.0.1\n"))
	if err != nil || len(got) != 1 || got[0].Line != 1 {
		t.Errorf("headerless: %+v %v", got, err)
	}
	if _, err := ParseCSV(strings.NewReader("a,\"b\n")); err == nil {
		t.Error("broken quoting must fail")
	}
}

func TestParseJSON(t *testing.T) {
	in := `[
  {"value": "10.20.0.0/24", "tags": ["lab"]},
  {"value": "10.20.1.1", "tags": "a;b"},

  {"value": "10.20.1.2"},
  {"value": "10.20.1.3", "tags": 5}
]`
	got, err := ParseJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %+v", got)
	}
	lines := []int{got[0].Line, got[1].Line, got[2].Line, got[3].Line}
	if !reflect.DeepEqual(lines, []int{2, 3, 5, 6}) {
		t.Errorf("lines = %v", lines)
	}
	if !reflect.DeepEqual(got[1].Tags, []string{"a", "b"}) || got[3].Err == nil {
		t.Errorf("entries = %+v", got)
	}
	for _, bad := range []string{`{"value":"x"}`, `[{"value": 1}]`, `[`, ``} {
		if _, err := ParseJSON([]byte(bad)); err == nil {
			t.Errorf("ParseJSON(%q) must fail", bad)
		}
	}
}

func TestParseLines(t *testing.T) {
	in := "10.20.0.0/24 web;x\n\n# skip\n  10.20.1.10  \napp.lab.test,dmz\n"
	got, err := ParseLines(strings.NewReader(in), []string{"form"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Line: 1, Value: "10.20.0.0/24", Tags: []string{"form", "web", "x"}},
		{Line: 4, Value: "10.20.1.10", Tags: []string{"form"}},
		{Line: 5, Value: "app.lab.test", Tags: []string{"form", "dmz"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name, data string
		want       Format
	}{
		{"a.CSV", "", FormatCSV},
		{"a.json", "", FormatJSON},
		{"a.txt", "1,2", FormatLines},
		{"x", "\xef\xbb\xbf  [{}]", FormatJSON},
		{"x", "value,tags\n", FormatCSV},
		{"x", "10.20.0.1\n10.20.0.2\n", FormatLines},
	}
	for _, c := range cases {
		if got := DetectFormat(c.name, []byte(c.data)); got != c.want {
			t.Errorf("DetectFormat(%q, %q) = %s, want %s", c.name, c.data, got, c.want)
		}
	}
}

func TestExportRoundTrip(t *testing.T) {
	ts := []model.Target{
		{Kind: model.TargetCIDR, Value: "10.20.0.0/24", Tags: []string{"lab", "web"}},
		{Kind: model.TargetIP, Value: "10.20.1.10"},
		{Kind: model.TargetDomain, Value: "app.lab.test", Tags: []string{"x"}},
	}
	for _, f := range []Format{FormatCSV, FormatJSON} {
		var buf bytes.Buffer
		var err error
		if f == FormatCSV {
			err = WriteCSV(&buf, ts)
		} else {
			err = WriteJSON(&buf, ts)
		}
		if err != nil {
			t.Fatal(err)
		}
		entries, err := ParseInput(DetectFormat("", buf.Bytes()), buf.Bytes())
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(entries) != len(ts) {
			t.Fatalf("%s: %+v", f, entries)
		}
		for i, e := range entries {
			tags, _ := NormalizeTags(e.Tags)
			if e.Value != ts[i].Value || strings.Join(tags, ";") != strings.Join(ts[i].Tags, ";") {
				t.Errorf("%s: entry %d = %+v, want %+v", f, i, e, ts[i])
			}
		}
	}
}
