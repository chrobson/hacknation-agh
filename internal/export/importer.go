package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/dojo"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// MaxImportSize caps an uploaded import file (kept in memory only).
const MaxImportSize = 32 << 20

// Format of an import file.
type Format string

const (
	FormatUnknown Format = ""
	FormatNmapXML Format = "nmap-xml"
	FormatGeneric Format = "generic-findings"
)

// ErrUnknownFormat is returned for files that are neither nmap XML nor
// Generic Findings JSON.
var ErrUnknownFormat = errors.New("unknown import format: expected nmap XML or DefectDojo Generic Findings JSON")

// DetectFormat sniffs the file content.
func DetectFormat(b []byte) Format {
	t := bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
	switch {
	case bytes.HasPrefix(t, []byte("<")) && bytes.Contains(t[:min(len(t), 4096)], []byte("<nmaprun")):
		return FormatNmapXML
	case bytes.HasPrefix(t, []byte("{")) && bytes.Contains(t, []byte(`"findings"`)):
		return FormatGeneric
	}
	return FormatUnknown
}

// Report summarises an import.
type Report struct {
	RunID      int64    `json:"run_id"`
	Format     Format   `json:"format"`
	Hosts      int      `json:"hosts"`
	Services   int      `json:"services"`
	Detections int      `json:"detections"`
	Errors     []string `json:"errors"`
}

// Parse converts an import file to observations without touching the DB.
func Parse(b []byte) (Format, Observations, error) {
	switch f := DetectFormat(b); f {
	case FormatNmapXML:
		o, err := ParseNmapXML(b)
		return f, o, err
	case FormatGeneric:
		fs, err := dojo.NewCodec().Unmarshal(b)
		if err != nil {
			return f, Observations{}, err
		}
		return f, FromFindings(fs), nil
	}
	return FormatUnknown, Observations{}, ErrUnknownFormat
}

var titlePrefixes = []struct{ prefix, category string }{
	{"Admin panel detected: ", "admin-panel"},
	{"Staging environment detected: ", "staging"},
	{"Technology detected: ", ""},
}

var knownCategories = map[string]bool{
	"cms": true, "framework": true, "server": true, "iot": true,
	"admin-panel": true, "staging": true, "other": true,
}

// FromFindings maps Generic Findings to observations. A finding with a
// vuln_id_from_tool (or an asi:sig: unique id) becomes a detection on its
// endpoints, anything else a service. Endpoints whose host is not an IP
// address are resolved from an ASI unique id when possible, otherwise they
// are reported and skipped (imports never perform DNS lookups).
func FromFindings(fs []model.Finding) Observations {
	var obs Observations
	hostSeen := map[model.AssetKey]bool{}
	svcSeen := map[model.AssetKey]bool{}
	addHost := func(k model.AssetKey) {
		hk := model.AssetKey{IP: k.IP}
		if !hostSeen[hk] {
			hostSeen[hk] = true
			obs.Hosts = append(obs.Hosts, model.HostObs{IP: k.IP, Up: true})
		}
	}
	addSvc := func(s model.ServiceObs) {
		if s.Key.Port == 0 {
			return
		}
		if svcSeen[s.Key] {
			// Fill gaps of an earlier record for the same key.
			for i := range obs.Services {
				if obs.Services[i].Key == s.Key && obs.Services[i].Product == "" {
					obs.Services[i].Product, obs.Services[i].Version = s.Product, s.Version
				}
			}
			return
		}
		svcSeen[s.Key] = true
		obs.Services = append(obs.Services, s)
	}

	for i, f := range fs {
		sigID := f.VulnIDFromTool
		if sigID == "" && strings.HasPrefix(f.UniqueIDFromTool, "asi:sig:") {
			if j := strings.LastIndexByte(f.UniqueIDFromTool, ':'); j >= 0 {
				sigID = strings.SplitN(f.UniqueIDFromTool[j+1:], "@", 2)[0]
			}
		}
		if len(f.Endpoints) == 0 {
			obs.Errors = append(obs.Errors, fmt.Sprintf("finding %d (%q): no endpoints, skipped", i, f.Title))
			continue
		}
		for _, k := range f.Endpoints {
			if !k.IP.IsValid() {
				ip, port, ok := dojo.ParseUniqueID(f.UniqueIDFromTool)
				if !ok {
					obs.Errors = append(obs.Errors, fmt.Sprintf("finding %d (%q): host %q is not an IP address, skipped", i, f.Title, k.VHost))
					continue
				}
				k.IP = ip
				if k.Port == 0 {
					k.Port = port
				}
				if k.Proto == "" && k.Port != 0 {
					k.Proto = "tcp"
				}
			}
			addHost(k)
			if sigID == "" {
				product, version := descriptionField(f.Description, "Product"), descriptionField(f.Description, "Version")
				// Our own export writes the product in the description; its
				// title ("Open service 22/tcp") is not a product name.
				if product == "" && !strings.HasPrefix(f.UniqueIDFromTool, "asi:") {
					product = strings.TrimSpace(f.Title)
				}
				addSvc(model.ServiceObs{Key: k, Product: product, Version: version})
				continue
			}
			addSvc(model.ServiceObs{Key: k})
			if k.Port == 0 {
				obs.Errors = append(obs.Errors, fmt.Sprintf("finding %d (%q): detection without port, skipped", i, f.Title))
				continue
			}
			name, cat := strings.TrimSpace(f.Title), ""
			for _, p := range titlePrefixes {
				if strings.HasPrefix(name, p.prefix) {
					name, cat = strings.TrimPrefix(name, p.prefix), p.category
					break
				}
			}
			if cat == "" {
				for _, t := range f.Tags {
					if knownCategories[strings.ToLower(t)] {
						cat = strings.ToLower(t)
						break
					}
				}
			}
			if cat == "" {
				cat = "other"
			}
			obs.Detections = append(obs.Detections, ImportedDetection{Key: k, Detection: model.Detection{
				SignatureID: sigID, Name: name, Category: cat, Confidence: 100,
				Evidence: map[string]string{"source": "import", "title": f.Title},
			}})
		}
	}
	return obs
}

// descriptionField reads "- <label>: value" lines written by BuildFindings.
func descriptionField(desc, label string) string {
	prefix := "- " + label + ": "
	for _, l := range strings.Split(desc, "\n") {
		if strings.HasPrefix(l, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(l, prefix))
		}
	}
	return ""
}

// AllowHost limits imported hosts to the allowed networks. The integrator
// sets it from ASI_ALLOWED_CIDRS; nil accepts every address.
var AllowHost func(netip.Addr) bool

// FilterAllowed drops hosts, services and detections outside allow and
// reports each dropped host in obs.Errors.
func FilterAllowed(obs Observations, allow func(netip.Addr) bool) Observations {
	if allow == nil {
		return obs
	}
	out := Observations{Errors: obs.Errors}
	dropped := map[netip.Addr]bool{}
	ok := func(ip netip.Addr) bool {
		if allow(ip) {
			return true
		}
		if !dropped[ip] {
			dropped[ip] = true
			out.Errors = append(out.Errors, fmt.Sprintf("host %s: outside allowed networks, skipped", ip))
		}
		return false
	}
	for _, h := range obs.Hosts {
		if ok(h.IP) {
			out.Hosts = append(out.Hosts, h)
		}
	}
	for _, s := range obs.Services {
		if ok(s.Key.IP) {
			out.Services = append(out.Services, s)
		}
	}
	for _, d := range obs.Detections {
		if ok(d.Key.IP) {
			out.Detections = append(out.Detections, d)
		}
	}
	return out
}

// Import parses a file and stores it as one scan_run of kind "import" in a
// single transaction. Hosts outside AllowHost are dropped.
func Import(ctx context.Context, pool *pgxpool.Pool, b []byte) (Report, error) {
	if len(b) > MaxImportSize {
		return Report{}, fmt.Errorf("import file larger than %d bytes", MaxImportSize)
	}
	format, obs, err := Parse(b)
	if err != nil {
		return Report{Format: format}, err
	}
	obs = FilterAllowed(obs, AllowHost)
	rep := Report{Format: format, Errors: obs.Errors}
	if len(obs.Hosts) == 0 {
		return rep, errors.New("nothing to import")
	}
	if pool == nil {
		return rep, errors.New("no database connection")
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		if rep.RunID, err = Store(ctx, tx, obs, &rep); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return Report{Format: format, Errors: obs.Errors}, err
	}
	return rep, nil
}

// Store writes observations as a new import run inside tx.
func Store(ctx context.Context, tx pgx.Tx, obs Observations, rep *Report) (int64, error) {
	runID, err := store.ImportBeginRun(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, h := range obs.Hosts {
		if err := store.ImportHost(ctx, tx, runID, h); err != nil {
			return 0, fmt.Errorf("host %s: %w", h.IP, err)
		}
		rep.Hosts++
	}
	ids := map[model.AssetKey]int64{}
	for _, s := range obs.Services {
		id, err := store.ImportService(ctx, tx, runID, s)
		if err != nil {
			return 0, fmt.Errorf("service %s:%d: %w", s.Key.IP, s.Key.Port, err)
		}
		if _, dup := ids[s.Key]; !dup {
			rep.Services++
		}
		ids[s.Key] = id
	}
	for _, d := range obs.Detections {
		id, ok := ids[d.Key]
		if !ok {
			continue
		}
		d.ServiceID = id
		if err := store.ImportDetection(ctx, tx, d.Detection); err != nil {
			return 0, fmt.Errorf("detection %s: %w", d.SignatureID, err)
		}
		rep.Detections++
	}
	if err := store.ImportFinishRun(ctx, tx, runID); err != nil {
		return 0, err
	}
	return runID, nil
}
