package sig

import (
	"context"
	"errors"
	"net/http"

	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
)

// HTTPFetcher adapts httpfp.HTTPProber to Fetcher: probes go to the origin
// of the observed URL, dial only the service IP and never follow redirects.
type HTTPFetcher struct {
	Prober *httpfp.HTTPProber
}

// NewHTTPFetcher returns a Fetcher backed by p (sharing its rate limiter).
func NewHTTPFetcher(p *httpfp.HTTPProber) *HTTPFetcher { return &HTTPFetcher{Prober: p} }

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context, svc model.ServiceObs, obs model.HTTPObs, req ProbeRequest) (ProbeResponse, error) {
	if f == nil || f.Prober == nil {
		return ProbeResponse{}, errors.New("sig: no prober")
	}
	if !svc.Key.IP.IsValid() {
		return ProbeResponse{}, errors.New("sig: service without IP")
	}
	var hdr http.Header
	if len(req.Headers) > 0 {
		hdr = http.Header{}
		for k, v := range req.Headers {
			hdr.Set(k, v)
		}
	}
	r, err := f.Prober.FetchPath(ctx, svc.Key.IP.Unmap().String(), svc.Key.VHost, obs.URL, req.Method, req.Path, hdr)
	if err != nil {
		return ProbeResponse{}, err
	}
	return ProbeResponse{Status: r.Status, Header: r.Header, Body: r.Body}, nil
}
