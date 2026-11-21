// Package signatures embeds the built-in detection signatures (*.yaml).
// The same files are copied to /etc/asi/signatures in the container image.
package signatures

import "embed"

// FS holds the built-in signature files.
//
//go:embed *.yaml
var FS embed.FS
