// Package changes embeds the HTML templates of the diff module (changes,
// host states, annotations) so the asi binary does not depend on files next
// to it at runtime.
package changes

import "embed"

// FS holds the module templates (*.html). They expect a "base" template
// (web/templates/base.html) to be parsed into the same set.
//
//go:embed *.html
var FS embed.FS
