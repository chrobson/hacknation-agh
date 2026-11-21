package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/web"
)

// CookieName is the session cookie.
const CookieName = "asi_session"

// SessionTTL is the lifetime of a session.
const SessionTTL = 12 * time.Hour

type ctxKey struct{}

// WithUser returns a context carrying u.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// UserFrom returns the authenticated user or nil.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}

// Funcs returns template helpers. "can" takes the user and a permission:
//
//	{{if can .User "scans.run"}}...{{end}}
func Funcs() template.FuncMap {
	return template.FuncMap{"can": can}
}

// sessionLookup resolves a session token hash to a user (nil, nil if none).
type sessionLookup func(ctx context.Context, tokenHash []byte) (*User, error)

// Middleware returns the global middleware: CSRF protection followed by
// session loading. Apply it with r.Use before mounting any module.
func Middleware(d web.Deps) func(http.Handler) http.Handler {
	lookup := func(ctx context.Context, h []byte) (*User, error) {
		au, err := store.SessionUser(ctx, d.DB, h)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return userFromStore(au), nil
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return CSRF(loadSession(lookup, log, next))
	}
}

func userFromStore(au store.AuthUser) *User {
	return &User{ID: au.ID, Login: au.Login, RoleID: au.RoleID, RoleName: au.RoleName, Perms: au.Perms}
}

func loadSession(lookup sessionLookup, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		u, err := lookup(r.Context(), hashToken(c.Value))
		if err != nil {
			log.Error("session lookup", "err", err)
			http.Error(w, "Błąd serwera", http.StatusInternalServerError)
			return
		}
		if u != nil {
			r = r.WithContext(WithUser(r.Context(), u))
		}
		next.ServeHTTP(w, r)
	})
}

// CSRF rejects cross-origin unsafe requests using http.CrossOriginProtection
// (Sec-Fetch-Site / Origin vs Host). Together with SameSite=Lax cookies this
// replaces CSRF tokens.
func CSRF(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeForbidden(w, r, "", "Żądanie z innej domeny zostało odrzucone (ochrona CSRF).")
	}))
	return cop.Handler(next)
}

// RequireAuth lets only authenticated users through. Unauthenticated page
// requests are redirected to /login; API and htmx requests get 401 JSON.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFrom(r.Context()) == nil {
			unauthorized(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Require returns middleware that demands perm. Missing session behaves like
// RequireAuth; a missing permission yields 403 (JSON for API/htmx requests,
// an HTML page otherwise).
func Require(perm Perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := UserFrom(r.Context())
			if u == nil {
				unauthorized(w, r)
				return
			}
			if !u.Can(perm) {
				writeForbidden(w, r, perm, "Brak uprawnienia: "+perm)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsAPIRequest reports whether the client expects JSON instead of a page:
// /api/ paths, htmx requests and Accept: application/json.
func IsAPIRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") || r.Header.Get("HX-Request") == "true" {
		return true
	}
	acc := r.Header.Get("Accept")
	return strings.Contains(acc, "application/json") && !strings.Contains(acc, "text/html")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	if IsAPIRequest(r) {
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	next := r.URL.RequestURI()
	if r.Method != http.MethodGet {
		next = "/"
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

func writeForbidden(w http.ResponseWriter, r *http.Request, perm, msg string) {
	if IsAPIRequest(r) {
		body := map[string]string{"error": "forbidden", "message": msg}
		if perm != "" {
			body["perm"] = perm
		}
		writeJSON(w, http.StatusForbidden, body)
		return
	}
	data := pageData{User: UserFrom(r.Context()), Message: msg}
	renderStatus(w, http.StatusForbidden, "forbidden.html", data)
}

// newToken returns a random session token for the cookie.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// isTLS reports whether the client connection is HTTPS (directly or via a
// TLS-terminating proxy).
func isTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, tok string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    tok,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}
