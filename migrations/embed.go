// Package migrations embeds the SQL schema migrations applied by internal/db.
package migrations

import "embed"

// FS holds all *.sql migration files. Files are applied in lexical order
// and recorded in the schema_migrations table.
//
//go:embed *.sql
var FS embed.FS
