package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/model"
)

// InstanceHeader marks every response of the asi web UI with the instance
// id, so the post-scan pipeline can recognise the scanner's own interface
// when a scan covers the host it runs on (localhost, host.docker.internal).
// A port number cannot do that: the UI listens on 9080 inside the container
// but is published on ASI_PORT, which the container does not know.
const InstanceHeader = "X-Asi-Instance"

// InstanceID is shared by every process of one installation (`asi serve` and
// CLI commands such as `asi scan` run in separate processes): an HMAC of
// ASI_SECRET_KEY, or of the database URL when no key is set. The value
// reveals neither input.
func InstanceID(cfg config.Config) string {
	key := cfg.SecretKey
	if len(key) == 0 {
		key = []byte(cfg.DatabaseURL)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("asi-instance-id"))
	return hex.EncodeToString(m.Sum(nil)[:12])
}

// isSelf reports whether an HTTP observation came from this installation's
// own web UI.
func isSelf(obs model.HTTPObs, self string) bool {
	if self == "" {
		return false
	}
	for _, v := range obs.Headers[InstanceHeader] {
		if v == self {
			return true
		}
	}
	return false
}

// instanceHeader sets InstanceHeader on every response.
func instanceHeader(id string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(InstanceHeader, id)
			next.ServeHTTP(w, r)
		})
	}
}
