package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// Entry is one raw input record before validation.
type Entry struct {
	Line  int // 1-based source line (CSV/JSON/textarea), 0 if unknown
	Value string
	Tags  []string
	Err   error // decode-level problem with this record (reported as is)
}

// ImportError describes one rejected input record.
type ImportError struct {
	Line  int    `json:"line"`
	Value string `json:"value"`
	Error string `json:"error"`
}

// Report is the outcome of an import. Its JSON form matches
// testdata/import/report.example.json.
type Report struct {
	Imported   int           `json:"imported"`
	Duplicates int           `json:"duplicates"`
	Errors     []ImportError `json:"errors"`
}

// Resolver resolves host names. *net.Resolver satisfies it; tests inject a
// fake so no DNS traffic is ever sent.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ErrNoAddresses is returned when a domain resolves to nothing.
var ErrNoAddresses = errors.New("domain does not resolve to any address")

// DefaultLookupTimeout bounds a single DNS lookup during import.
const DefaultLookupTimeout = 3 * time.Second

// Importer validates entries against the allowlist. Domains are resolved and
// every resolved address must lie inside the allowlist.
type Importer struct {
	Allow         Allowlist
	Resolver      Resolver      // nil = net.DefaultResolver
	LookupTimeout time.Duration // 0 = DefaultLookupTimeout
}

// Prepare parses, normalizes, allowlist-checks and dedupes entries. It
// returns the targets to store and a report with Errors and in-batch
// Duplicates filled in; Imported is left for the caller (see Finish).
// Tags of in-batch duplicates are merged into the first occurrence.
func (im Importer) Prepare(ctx context.Context, entries []Entry) ([]model.Target, Report) {
	rep := Report{Errors: []ImportError{}}
	var out []model.Target
	index := map[string]int{}
	checked := im.checkAll(ctx, entries)
	for i, e := range entries {
		t, err := checked[i].t, checked[i].err
		if err == nil {
			t.Tags, err = NormalizeTags(e.Tags)
		}
		if err != nil {
			rep.Errors = append(rep.Errors, ImportError{Line: e.Line, Value: e.Value, Error: err.Error()})
			continue
		}
		if i, ok := index[t.Value]; ok {
			rep.Duplicates++
			if merged, err := NormalizeTags(append(out[i].Tags, t.Tags...)); err == nil {
				out[i].Tags = merged
			}
			continue
		}
		index[t.Value] = len(out)
		out = append(out, t)
	}
	return out, rep
}

// importWorkers bounds concurrent DNS lookups during one import.
const importWorkers = 16

type checkResult struct {
	t   model.Target
	err error
}

// checkAll runs Check for every entry; domain lookups run concurrently so a
// list of names is not resolved strictly one after another.
func (im Importer) checkAll(ctx context.Context, entries []Entry) []checkResult {
	res := make([]checkResult, len(entries))
	sem := make(chan struct{}, importWorkers)
	var wg sync.WaitGroup
	for i, e := range entries {
		if e.Err != nil {
			res[i].err = e.Err
			continue
		}
		t, err := Parse(e.Value)
		if err != nil || t.Kind != model.TargetDomain {
			// IPs and CIDRs need no I/O: check them inline.
			res[i].t, res[i].err = im.Check(ctx, e.Value)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, v string) {
			defer wg.Done()
			defer func() { <-sem }()
			res[i].t, res[i].err = im.Check(ctx, v)
		}(i, e.Value)
	}
	wg.Wait()
	return res
}

// Finish records how many of the prepared targets were actually inserted;
// the rest already existed in the database and count as duplicates.
func (r *Report) Finish(prepared, inserted int) {
	r.Imported += inserted
	r.Duplicates += prepared - inserted
}

// Check parses one value and enforces the allowlist on it.
func (im Importer) Check(ctx context.Context, value string) (model.Target, error) {
	t, err := Parse(value)
	if err != nil {
		return t, err
	}
	if p, ok := TargetPrefix(t); ok {
		if !im.Allow.AllowsPrefix(p) {
			return t, ErrNotAllowed
		}
		return t, nil
	}
	addrs, err := im.resolve(ctx, t.Value)
	if err != nil {
		return t, err
	}
	for _, a := range addrs {
		if !im.Allow.AllowsAddr(a) {
			return t, ErrNotAllowed
		}
	}
	return t, nil
}

func (im Importer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	res := im.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	to := im.LookupTimeout
	if to <= 0 {
		to = DefaultLookupTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	addrs, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, ErrNoAddresses
	}
	return addrs, nil
}

// ResolvePrefixes turns stored targets into scan prefixes: IP/CIDR targets
// directly, domains by resolving them now. Every prefix is checked against
// the allowlist again; a target outside it fails the whole call so a run
// never silently scans less (or more) than configured. Duplicates are removed.
func (im Importer) ResolvePrefixes(ctx context.Context, ts []model.Target) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, t := range ts {
		if p, ok := TargetPrefix(t); ok {
			if !im.Allow.AllowsPrefix(p) {
				return nil, fmt.Errorf("%w: %s", ErrNotAllowed, p)
			}
			add(p)
			continue
		}
		addrs, err := im.resolve(ctx, t.Value)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			a = a.Unmap()
			if !im.Allow.AllowsAddr(a) {
				return nil, fmt.Errorf("%w: %s (%s)", ErrNotAllowed, t.Value, a)
			}
			add(netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}
