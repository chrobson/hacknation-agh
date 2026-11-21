package target

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// Input limits shared by the web form, file upload and CLI import.
const (
	MaxImportBytes   = 5 << 20
	MaxImportEntries = 20000
)

// ErrTooManyEntries is returned when an input exceeds MaxImportEntries.
var ErrTooManyEntries = fmt.Errorf("too many entries (max %d)", MaxImportEntries)

// Format is a target list encoding.
type Format string

const (
	FormatCSV   Format = "csv"
	FormatJSON  Format = "json"
	FormatLines Format = "lines"
)

// DetectFormat picks a format from the file name, falling back to content
// sniffing: a leading '[' means JSON, a comma in the first line means CSV.
func DetectFormat(name string, data []byte) Format {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		return FormatJSON
	case ".csv":
		return FormatCSV
	case ".txt":
		return FormatLines
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return FormatJSON
	}
	first, _, _ := bytes.Cut(trimmed, []byte("\n"))
	if bytes.Contains(first, []byte(",")) {
		return FormatCSV
	}
	return FormatLines
}

// ParseInput decodes data in the given format into raw entries.
func ParseInput(f Format, data []byte) ([]Entry, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	switch f {
	case FormatCSV:
		return ParseCSV(bytes.NewReader(data))
	case FormatJSON:
		return ParseJSON(data)
	default:
		return ParseLines(bytes.NewReader(data), nil)
	}
}

// ParseCSV reads "value,tags" rows; tags are separated by ';'. A header row
// whose first cell is "value" is skipped. Line numbers are source lines, so
// the header is line 1.
func ParseCSV(r io.Reader) ([]Entry, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'
	var out []Entry
	first := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("csv: %w", err)
		}
		line, _ := cr.FieldPos(0)
		if first {
			first = false
			if strings.EqualFold(strings.TrimSpace(rec[0]), "value") {
				continue
			}
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		e := Entry{Line: line, Value: strings.TrimSpace(rec[0])}
		for _, cell := range rec[1:] {
			e.Tags = append(e.Tags, SplitTags(cell)...)
		}
		out = append(out, e)
		if len(out) > MaxImportEntries {
			return nil, ErrTooManyEntries
		}
	}
	return out, nil
}

type jsonEntry struct {
	Value string          `json:"value"`
	Tags  json.RawMessage `json:"tags"`
}

// ParseJSON reads [{"value": "...", "tags": ["a","b"]}]. Tags may also be a
// single "a;b" string. Each entry's Line is the source line where its object
// starts.
func ParseJSON(data []byte) ([]Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, errors.New("json: expected an array of {value, tags} objects")
	}
	var out []Entry
	for dec.More() {
		start := skipSep(data, int(dec.InputOffset()))
		line := 1 + bytes.Count(data[:start], []byte("\n"))
		var je jsonEntry
		if err := dec.Decode(&je); err != nil {
			return out, fmt.Errorf("json (line %d): %w", line, err)
		}
		tags, err := decodeTags(je.Tags)
		out = append(out, Entry{Line: line, Value: strings.TrimSpace(je.Value), Tags: tags, Err: err})
		if len(out) > MaxImportEntries {
			return nil, ErrTooManyEntries
		}
	}
	if _, err := dec.Token(); err != nil {
		return out, fmt.Errorf("json: %w", err)
	}
	return out, nil
}

func decodeTags(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return SplitTags(s), nil
	}
	return nil, errors.New("tags must be a list of strings")
}

func skipSep(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\r', '\n', ',':
			i++
		default:
			return i
		}
	}
	return i
}

// ParseLines reads one target per line (the web textarea). Blank lines and
// lines starting with '#' are skipped. A line may carry its own tags after
// whitespace or a comma: "10.20.0.0/24 lab;web". defaultTags are added to
// every entry.
func ParseLines(r io.Reader, defaultTags []string) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []Entry
	n := 0
	for sc.Scan() {
		n++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		value, rest := s, ""
		if i := strings.IndexAny(s, ", \t"); i >= 0 {
			value, rest = s[:i], strings.TrimLeft(s[i+1:], ", \t")
		}
		e := Entry{Line: n, Value: value}
		e.Tags = append(append([]string{}, defaultTags...), SplitTags(rest)...)
		out = append(out, e)
		if len(out) > MaxImportEntries {
			return nil, ErrTooManyEntries
		}
	}
	return out, sc.Err()
}

// WriteCSV exports targets in the import CSV format (value,tags).
func WriteCSV(w io.Writer, ts []model.Target) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"value", "tags"}); err != nil {
		return err
	}
	for _, t := range ts {
		if err := cw.Write([]string{t.Value, strings.Join(t.Tags, ";")}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

type exportEntry struct {
	Value string   `json:"value"`
	Kind  string   `json:"kind"`
	Tags  []string `json:"tags"`
}

// WriteJSON exports targets in the import JSON format. The extra "kind"
// field is informational and ignored on import.
func WriteJSON(w io.Writer, ts []model.Target) error {
	out := make([]exportEntry, 0, len(ts))
	for _, t := range ts {
		tags := t.Tags
		if tags == nil {
			tags = []string{}
		}
		out = append(out, exportEntry{Value: t.Value, Kind: string(t.Kind), Tags: tags})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
