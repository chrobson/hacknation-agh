// Package httpfp fingerprints HTTP(S) endpoints. Owned by W1-3.
package httpfp

import (
	"context"

	"github.com/chrobson/hacknation-agh/internal/model"
)

// Prober fetches an endpoint (max 5 redirects, body capped at 2 MB) and
// records title, headers, cookies, TLS leaf certificate and favicon mmh3.
// Only GET/HEAD requests are ever sent.
type Prober interface {
	Probe(ctx context.Context, ep model.Endpoint) (model.HTTPObs, error)
}
