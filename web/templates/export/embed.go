// Package export embeds the HTML templates of the export/import pages
// (internal/export). Pages extend base.html, which the integrator provides
// through export.BaseTemplates.
package export

import "embed"

// FS holds index.html (export page) and import.html (upload page).
//
//go:embed index.html import.html
var FS embed.FS
