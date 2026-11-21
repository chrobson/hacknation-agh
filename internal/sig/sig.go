// Package sig loads and evaluates safe YAML detection signatures. Owned by W1-3.
package sig

import "github.com/chrobson/hacknation-agh/internal/model"

// Matcher evaluates signatures against observations. Signatures may only use
// GET/HEAD, at most 3 extra paths, no request body and no auth headers;
// anything else is rejected by the loader.
type Matcher interface {
	Match(svc model.ServiceObs, obs model.HTTPObs) []model.Detection
}
