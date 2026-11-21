// Package web wires HTTP routes. Each module exposes Mount(r, deps) and
// renders templates that extend web/templates/base.html.
package web

import (
	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/config"
)

// Deps are shared dependencies passed to every module's Mount.
type Deps struct {
	DB     *pgxpool.Pool
	Config config.Config
	Log    *slog.Logger
}

// Mounter registers a module's routes.
type Mounter func(r chi.Router, d Deps)
