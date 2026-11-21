// Package targets embeds the HTML templates of the targets module so the
// single asi binary does not depend on files next to it at runtime.
package targets

import "embed"

// FS holds the targets module templates (*.html). They expect a "base"
// template (web/templates/base.html) to be parsed into the same set.
//
//go:embed *.html
var FS embed.FS
