// Package app wires the modules into the running product: the post-scan
// pipeline (HTTP fingerprinting, signatures, diff), the router with all
// module pages, the dashboard, scan configuration pages, results pages and
// the lab verification used by `asi verify`.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/diff"
	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/sig"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// Pipeline is the post-processing of a finished scan run: every HTTP(S)
// service is fingerprinted (GET/HEAD only), signatures are matched on every
// service, and the run is compared with the previous one.
type Pipeline struct {
	Pool     *pgxpool.Pool
	Prober   *httpfp.HTTPProber
	Engine   *sig.Engine
	Unstable config.UnstableConfig
	Log      *slog.Logger
	Workers  int // parallel probes, default 8
	Now      func() time.Time
	// SelfID is InstanceID of this installation: services answering with it
	// in InstanceHeader are the scanner's own UI and get no detections (the
	// open port itself is still reported).
	SelfID string
}

// OnDone is the runner hook: fingerprint, then diff.ApplyRun.
func (p *Pipeline) OnDone(ctx context.Context, runID int64) error {
	t0 := time.Now()
	n, err := p.Fingerprint(ctx, runID)
	if err != nil {
		p.log().Error("fingerprinting failed", "run", runID, "err", err)
	}
	p.log().Info("fingerprinting done", "run", runID, "services", n, "ms", time.Since(t0).Milliseconds())
	if derr := p.ApplyDiff(ctx, runID); derr != nil {
		return errors.Join(err, derr)
	}
	return err
}

// ApplyDiff compares runID with the previous done run. Applying the same run
// twice is not an error.
func (p *Pipeline) ApplyDiff(ctx context.Context, runID int64) error {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	res, err := diff.ApplyRun(ctx, p.Pool, runID, diff.FromConfig(p.Unstable), now())
	if errors.Is(err, diff.ErrAlreadyApplied) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("diff run %d: %w", runID, err)
	}
	p.log().Info("diff applied", "run", runID, "result", fmt.Sprintf("%+v", res))
	return nil
}

func (p *Pipeline) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// Fingerprint probes and matches every service of the run. It returns the
// number of services processed.
func (p *Pipeline) Fingerprint(ctx context.Context, runID int64) (int, error) {
	svcs, err := store.DiffRunServices(ctx, p.Pool, runID)
	if err != nil {
		return 0, err
	}
	names, err := runHostnames(ctx, p.Pool, runID)
	if err != nil {
		return 0, err
	}
	k := p.Workers
	if k <= 0 {
		k = 8
	}
	jobs := make(chan model.ServiceObs)
	var mu sync.Mutex
	var errs error
	var wg sync.WaitGroup
	for w := 0; w < k; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				if err := p.service(ctx, s, names[s.Key.IP]); err != nil {
					mu.Lock()
					errs = errors.Join(errs, fmt.Errorf("%s: %w", diff.KeyString(s.Key), err))
					mu.Unlock()
				}
			}
		}()
	}
	for _, s := range svcs {
		if ctx.Err() != nil {
			break
		}
		jobs <- s
	}
	close(jobs)
	wg.Wait()
	return len(svcs), errs
}

func (p *Pipeline) service(ctx context.Context, s model.ServiceObs, hostnames []string) error {
	scheme := HTTPScheme(s)
	var obs model.HTTPObs
	if scheme != "" && p.Prober != nil {
		var o model.HTTPObs
		var err error
		o, scheme, err = probeScheme(ctx, p.Prober, model.Endpoint{ServiceID: s.ID, Key: s.Key, Scheme: scheme})
		ep := model.Endpoint{ServiceID: s.ID, Key: s.Key, Scheme: scheme}
		if err != nil {
			p.log().Debug("http probe failed", "service", diff.KeyString(s.Key), "err", err)
		}
		if o.Status != 0 || o.TLS != nil {
			obs = o
			if err := store.SaveHTTPObs(ctx, p.Pool, obs); err != nil {
				return fmt.Errorf("save http obs: %w", err)
			}
			if scheme == "https" {
				if lt, err := p.Prober.ProbeLegacyTLS(ctx, ep); err == nil {
					if err := store.SaveLegacyTLS(ctx, p.Pool, s.ID, lt); err != nil {
						return fmt.Errorf("save legacy tls: %w", err)
					}
				}
			}
		}
	}
	var dets []model.Detection
	if isSelf(obs, p.SelfID) {
		p.log().Debug("own web UI, detections skipped", "service", diff.KeyString(s.Key))
	} else if p.Engine != nil {
		dets = p.Engine.MatchContext(ctx, s, obs)
		// Names the address is known by (domain targets) are probed as
		// virtual hosts too: a staging vhost on a shared IP is otherwise
		// invisible. Detections are attached to the address' service.
		if scheme != "" && p.Prober != nil && s.Key.VHost == "" {
			for _, h := range hostnames {
				vs := s
				vs.Key.VHost = h
				vo, err := p.Prober.Probe(ctx, model.Endpoint{ServiceID: s.ID, Key: vs.Key, Scheme: scheme})
				if err != nil && vo.Status == 0 {
					vo = model.HTTPObs{ServiceID: s.ID}
				}
				dets = mergeDetections(dets, p.Engine.MatchContext(ctx, vs, vo))
			}
			dets = sig.SuppressGeneric(dets)
		}
	}
	for i := range dets {
		dets[i].ServiceID = s.ID
	}
	return store.ReplaceDetections(ctx, p.Pool, s.ID, dets)
}

// probeScheme probes ep and, when the scheme nmap suggested looks wrong,
// the other one, returning the observation that was kept and its scheme.
//   - A port labelled plain http that does not answer HTTP is retried over
//     TLS (nmap sometimes misses TLS).
//   - A port labelled ssl/http whose TLS answer is an empty 404 is retried
//     over plain http. Some servers accept both on one port (Traefik
//     entrypoints answer a TLS handshake with their default certificate but
//     route only plain HTTP there, e.g. the api.insecure dashboard), and the
//     plain answer is the one worth fingerprinting.
func probeScheme(ctx context.Context, pr httpfp.Prober, ep model.Endpoint) (model.HTTPObs, string, error) {
	o, err := pr.Probe(ctx, ep)
	switch {
	case err != nil && ep.Scheme == "http" && o.Status == 0:
		alt := ep
		alt.Scheme = "https"
		if o2, err2 := pr.Probe(ctx, alt); err2 == nil || o2.Status != 0 {
			return o2, "https", err2
		}
	case err == nil && ep.Scheme == "https" && o.Status == 404 && o.Title == "":
		alt := ep
		alt.Scheme = "http"
		if o2, err2 := pr.Probe(ctx, alt); err2 == nil && o2.Status != 0 && o2.Status != 404 {
			return o2, "http", nil
		}
	}
	return o, ep.Scheme, err
}

func mergeDetections(a, b []model.Detection) []model.Detection {
	idx := make(map[string]int, len(a))
	for i, d := range a {
		idx[d.SignatureID] = i
	}
	for _, d := range b {
		if i, ok := idx[d.SignatureID]; ok {
			if d.Confidence > a[i].Confidence {
				a[i] = d
			}
			continue
		}
		idx[d.SignatureID] = len(a)
		a = append(a, d)
	}
	return a
}

// webPorts are probed over HTTP even when nmap could not name the service.
var webPorts = map[uint16]string{
	80: "http", 81: "http", 3000: "http", 5000: "http", 8000: "http", 8008: "http",
	8080: "http", 8081: "http", 8088: "http", 8222: "http", 8888: "http", 9000: "http",
	443: "https", 8443: "https", 9443: "https",
}

// HTTPScheme returns "http" or "https" for services worth an HTTP probe and
// "" otherwise. The nmap service name is stored in Banner ("ssl/http").
func HTTPScheme(s model.ServiceObs) string {
	if s.Key.Proto != "" && s.Key.Proto != "tcp" {
		return ""
	}
	b := strings.ToLower(strings.TrimSuffix(s.Banner, "?"))
	switch {
	case strings.HasPrefix(b, "ssl/http"), strings.HasPrefix(b, "https"):
		return "https"
	case strings.HasPrefix(b, "http"):
		if s.Key.Port == 443 || s.Key.Port == 8443 || s.Key.Port == 9443 {
			return "https"
		}
		return "http"
	case b == "" || b == "unknown" || b == "tcpwrapped" || b == "ppp" || b == "hbci" ||
		b == "ssl/unknown" || b == "ssl":
		if sch, ok := webPorts[s.Key.Port]; ok {
			if strings.HasPrefix(b, "ssl") {
				return "https"
			}
			return sch
		}
		if strings.HasPrefix(b, "ssl") {
			return "https"
		}
	}
	return ""
}

func runHostnames(ctx context.Context, pool *pgxpool.Pool, runID int64) (map[netip.Addr][]string, error) {
	rows, err := pool.Query(ctx, `SELECT host(ip), hostname FROM host_obs WHERE run_id=$1 AND hostname <> ''`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[netip.Addr][]string{}
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		out[a] = append(out[a], name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	// Every domain target resolving to the address adds a vhost name (the
	// runner keeps only one hostname per address in host_obs).
	trows, err := pool.Query(ctx, `SELECT value FROM targets WHERE kind='domain' ORDER BY value`)
	if err != nil {
		return nil, err
	}
	var domains []string
	for trows.Next() {
		var d string
		if err := trows.Scan(&d); err == nil {
			domains = append(domains, d)
		}
	}
	trows.Close()
	for _, d := range domains {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := net.DefaultResolver.LookupNetIP(lctx, "ip", d)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			a = a.Unmap()
			if !slices.Contains(out[a], d) {
				out[a] = append(out[a], d)
			}
		}
	}
	return out, nil
}
