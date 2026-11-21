package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// SeedUser is a demo account created on first start.
type SeedUser struct {
	Login  string
	Role   string
	EnvVar string // password source; random when unset
}

// SeedUsers maps the four demo logins to the built-in roles.
var SeedUsers = []SeedUser{
	{"admin", RoleAdmin, "ASI_SEED_PASSWORD_ADMIN"},
	{"editor", RoleEditor, "ASI_SEED_PASSWORD_EDITOR"},
	{"analyst", RoleAnalyst, "ASI_SEED_PASSWORD_ANALYST"},
	{"viewer", RoleViewer, "ASI_SEED_PASSWORD_VIEWER"},
}

// Seed creates the demo users when the users table is empty. Passwords come
// from ASI_SEED_PASSWORD_{ADMIN,EDITOR,ANALYST,VIEWER}; missing ones are
// generated and printed once to stderr. It is a no-op once any user exists.
func Seed(ctx context.Context, pool *pgxpool.Pool, cfg config.Config) error {
	_ = cfg // reserved: seed settings may move into config
	_, err := seed(ctx, pool, os.Getenv, os.Stderr)
	return err
}

func seed(ctx context.Context, pool *pgxpool.Pool, getenv func(string) string, out io.Writer) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Serialize concurrent first starts.
	if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	n, err := store.CountUsers(ctx, tx)
	if err != nil || n > 0 {
		return false, err
	}
	type printed struct{ login, pw string }
	var generated []printed
	for _, su := range SeedUsers {
		pw := getenv(su.EnvVar)
		if pw == "" {
			pw = randomPassword()
			generated = append(generated, printed{su.Login, pw})
		}
		hash, err := HashPassword(pw)
		if err != nil {
			return false, fmt.Errorf("%s: %w", su.EnvVar, err)
		}
		roleID, err := store.RoleIDByName(ctx, tx, su.Role)
		if err != nil {
			return false, fmt.Errorf("role %q: %w", su.Role, err)
		}
		id, err := store.CreateUser(ctx, tx, su.Login, hash, roleID)
		if err != nil {
			return false, fmt.Errorf("create %s: %w", su.Login, err)
		}
		if err := store.InsertAudit(ctx, tx, nil, "user.seed", "user:"+su.Login,
			map[string]any{"user_id": id, "role": su.Role}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	for _, p := range generated {
		fmt.Fprintf(out, "asi: created demo user %q with password %s (shown once)\n", p.login, p.pw)
	}
	return true, nil
}

func randomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
