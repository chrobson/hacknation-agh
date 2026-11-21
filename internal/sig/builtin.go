package sig

import "github.com/chrobson/hacknation-agh/signatures"

// Builtin loads the signatures embedded from the signatures/ directory.
func Builtin() ([]*Signature, error) { return LoadFS(signatures.FS) }
