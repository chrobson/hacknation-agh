package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"github.com/chrobson/hacknation-agh/internal/auth"
	"github.com/chrobson/hacknation-agh/internal/diff"
	"github.com/chrobson/hacknation-agh/internal/export"
	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/runner"
	"github.com/chrobson/hacknation-agh/internal/scan"
	"github.com/chrobson/hacknation-agh/internal/sig"
	"github.com/chrobson/hacknation-agh/internal/store"
	"github.com/chrobson/hacknation-agh/internal/target"
	"github.com/chrobson/hacknation-agh/internal/web"
	webassets "github.com/chrobson/hacknation-agh/web"
)

// HTTPProbeRate is the global limit of HTTP requests per second sent by the
// fingerprinting stage (all workers together).
const HTTPProbeRate = 20

// Core holds the scanning machinery shared by `asi serve` and `asi scan`.
type Core struct {
	Deps     web.Deps
	Allow    target.Allowlist
	Prober   *httpfp.HTTPProber
	Engine   *sig.Engine
	Pipeline *Pipeline
	Runner   *runner.Runner
}

// NewCore syncs the built-in signatures, builds the prober, the signature
// engine, the post-scan pipeline and the runner, and sets the module hooks
// that do not depend on HTTP (diff after import, DefectDojo credentials).
func NewCore(ctx context.Context, d web.Deps) (*Core, error) {
	cfg := d.Config
	c := &Core{Deps: d, Allow: target.NewAllowlist(cfg.AllowedCIDRs)}
	if err := sig.SyncBuiltin(ctx, d.DB); err != nil {
		return nil, fmt.Errorf("sync built-in signatures: %w", err)
	}
	sigs, err := sig.LoadEnabled(ctx, d.DB)
	if err != nil {
		d.Log.Warn("some signatures failed to load", "err", err)
	}
	c.Prober = httpfp.New(httpfp.Options{
		Limiter:   rate.NewLimiter(rate.Limit(HTTPProbeRate), 5),
		Allow:     c.Allow.AllowsAddr,
		UserAgent: "asi-discovery/1.0 (+security inventory scan)",
	})
	c.Engine = sig.NewEngine(sigs, sig.NewHTTPFetcher(c.Prober))
	sig.OnChange = func(ctx context.Context) {
		s, err := sig.LoadEnabled(ctx, d.DB)
		if err != nil {
			d.Log.Warn("some signatures failed to load", "err", err)
		}
		c.Engine.SetSignatures(s)
	}
	c.Pipeline = &Pipeline{Pool: d.DB, Prober: c.Prober, Engine: c.Engine, Unstable: cfg.Unstable, Log: d.Log}

	sc := scan.NewNmap(cfg.NmapPath, c.Allow, cfg.ScanExclude...)
	c.Runner = runner.New(store.NewScanStore(d.DB), sc, c.Allow, cfg.ScanPrivileged, d.Log)
	c.Runner.OnDone = c.Pipeline.OnDone
	c.Runner.ExtraPorts = scan.DefaultExtraPorts
	c.Runner.MaxRate = cfg.MaxRate
	c.Runner.AllowedPorts = cfg.ScanPorts

	// Imports (nmap XML, Generic Findings) are compared like scan runs,
	// limited to the hosts in the file, and never store hosts outside the
	// allowed networks.
	export.AllowHost = c.Allow.AllowsAddr
	export.AfterImport = func(ctx context.Context, _ *pgxpool.Pool, runID int64) error {
		return c.Pipeline.ApplyDiff(ctx, runID)
	}
	export.DojoToken = func(ctx context.Context) (string, string, string, error) {
		if cfg.DojoToken != "" || cfg.DojoUser != "" {
			return cfg.DojoToken, cfg.DojoUser, cfg.DojoPassword, nil
		}
		tok, err := auth.GetSecret(ctx, d.DB, cfg, "dojo_token")
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, auth.ErrNoSecretKey) {
			return "", "", "", nil
		}
		return tok, "", "", err
	}
	return c, nil
}

// SetModuleHooks connects every module to internal/auth and to the embedded
// templates. Call it once before building the router.
func SetModuleHooks(tmpl fs.FS) {
	auth.SetTemplateFS(tmpl)
	target.BaseTemplates = tmpl
	target.Authz = auth.Authz{}
	diff.BaseTemplates = tmpl
	diff.Auth = diff.Access{
		Require: func(p string) func(http.Handler) http.Handler { return auth.Require(p) },
		Can: func(r *http.Request, p string) bool {
			u := auth.UserFrom(r.Context())
			return u != nil && u.Can(p)
		},
		UserID: func(r *http.Request) int64 {
			if u := auth.UserFrom(r.Context()); u != nil {
				return u.ID
			}
			return 0
		},
	}
	sig.TemplateFS = tmpl
	sig.Authorize = func(p string) func(http.Handler) http.Handler { return auth.Require(p) }
	sig.Can = func(r *http.Request, p string) bool {
		u := auth.UserFrom(r.Context())
		return u != nil && u.Can(p)
	}
	export.BaseTemplates = tmpl
	export.RequirePerm = func(p string) func(http.Handler) http.Handler { return auth.Require(p) }
	export.CurrentUserID = func(r *http.Request) *int64 {
		if u := auth.UserFrom(r.Context()); u != nil {
			id := u.ID
			return &id
		}
		return nil
	}
}

// Router builds the HTTP handler with every module mounted. base is the
// process lifetime context for runs started from the UI.
func Router(base context.Context, c *Core) (http.Handler, error) {
	SetModuleHooks(webassets.Templates)
	d := c.Deps
	pages, err := NewPages(d, c.Runner, base, webassets.Templates)
	if err != nil {
		return nil, err
	}
	r := chi.NewRouter()
	// No middleware.RealIP: the app is reached directly (published on
	// 127.0.0.1), so X-Forwarded-For would let any client choose the address
	// written to the audit log and used for login throttling.
	r.Use(middleware.Recoverer, securityHeaders)
	r.Handle("/static/*", http.StripPrefix("/static/", staticHandler(webassets.Static)))
	r.Group(func(r chi.Router) {
		// Session + CSRF (CrossOriginProtection) before any module.
		r.Use(auth.Middleware(d))
		auth.Mount(r, d)
		pages.Mount(r)
		r.Group(func(r chi.Router) {
			// Anonymous visitors are sent to /login like on every other page
			// (the targets module itself only knows allowed / 403).
			r.Use(auth.RequireAuth)
			target.Mount(r, d)
		})
		sig.Mount(r, d)
		diff.Mount(r, d)
		export.Mount(r, d)
	})
	return r, nil
}

func staticHandler(fsys fs.FS) http.Handler {
	h := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// Serve runs the HTTP server until ctx is done, then shuts down gracefully.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}
