// Package webassets embeds the shared web templates and static files so the
// asi binary is self-contained (the runtime image ships only the binary).
package webassets

import (
	"embed"
	"io/fs"
)

// all: keeps partials whose names start with "_" (e.g. admin/_nav.html).
//
//go:embed all:templates static
var embedded embed.FS

// Templates is rooted at web/templates (base.html, admin/, sig/, app/, ...).
var Templates fs.FS = mustSub("templates")

// Static is rooted at web/static (app.css, htmx.min.js).
var Static fs.FS = mustSub("static")

func mustSub(dir string) fs.FS {
	f, err := fs.Sub(embedded, dir)
	if err != nil {
		panic(err)
	}
	return f
}
