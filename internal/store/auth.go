// Package store holds plain pgx queries, one file per module.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// AuthDB is satisfied by both *pgxpool.Pool and pgx.Tx.
type AuthDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrRoleInUse is returned when deleting a role that users still have.
var ErrRoleInUse = errors.New("role is assigned to users")

// ErrRoleBuiltin is returned when deleting a built-in role.
var ErrRoleBuiltin = errors.New("built-in role cannot be deleted")

// AuthUser is a user row joined with its role and permissions.
type AuthUser struct {
	ID        int64
	Login     string
	PassHash  string
	RoleID    int64
	RoleName  string
	Perms     []string
	CreatedAt time.Time
}

// AuthRole is a role with its permissions and number of assigned users.
type AuthRole struct {
	ID      int64
	Name    string
	Builtin bool
	Perms   []string
	Users   int
}

// AuditEntry is one audit_log row with the actor's login resolved.
type AuditEntry struct {
	ID      int64
	At      time.Time
	UserID  *int64
	Login   string
	Action  string
	Entity  string
	Details string
}

const authUserCols = `u.id, u.login, u.pass_hash, u.role_id, r.name,
	COALESCE((SELECT array_agg(rp.perm ORDER BY rp.perm) FROM role_permissions rp WHERE rp.role_id = u.role_id), '{}'),
	u.created_at`

func scanAuthUser(row pgx.Row) (AuthUser, error) {
	var u AuthUser
	err := row.Scan(&u.ID, &u.Login, &u.PassHash, &u.RoleID, &u.RoleName, &u.Perms, &u.CreatedAt)
	return u, err
}

// CountUsers returns the number of users.
func CountUsers(ctx context.Context, q AuthDB) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// RoleIDByName resolves a role name.
func RoleIDByName(ctx context.Context, q AuthDB, name string) (int64, error) {
	var id int64
	err := q.QueryRow(ctx, `SELECT id FROM roles WHERE name = $1`, name).Scan(&id)
	return id, err
}

// CreateUser inserts a user and returns its id.
func CreateUser(ctx context.Context, q AuthDB, login, passHash string, roleID int64) (int64, error) {
	var id int64
	err := q.QueryRow(ctx,
		`INSERT INTO users (login, pass_hash, role_id) VALUES ($1, $2, $3) RETURNING id`,
		login, passHash, roleID).Scan(&id)
	return id, err
}

// UserByLogin loads a user (with password hash) by login. Returns
// pgx.ErrNoRows when absent.
func UserByLogin(ctx context.Context, q AuthDB, login string) (AuthUser, error) {
	return scanAuthUser(q.QueryRow(ctx,
		`SELECT `+authUserCols+` FROM users u JOIN roles r ON r.id = u.role_id WHERE u.login = $1`, login))
}

// UserByID loads a user by id.
func UserByID(ctx context.Context, q AuthDB, id int64) (AuthUser, error) {
	return scanAuthUser(q.QueryRow(ctx,
		`SELECT `+authUserCols+` FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, id))
}

// ListUsers returns all users ordered by login.
func ListUsers(ctx context.Context, q AuthDB) ([]AuthUser, error) {
	rows, err := q.Query(ctx,
		`SELECT `+authUserCols+` FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.login`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthUser
	for rows.Next() {
		u, err := scanAuthUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserRole changes a user's role.
func SetUserRole(ctx context.Context, q AuthDB, userID, roleID int64) error {
	tag, err := q.Exec(ctx, `UPDATE users SET role_id = $2 WHERE id = $1`, userID, roleID)
	if err == nil && tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}

// CreateSession stores a session token hash.
func CreateSession(ctx context.Context, q AuthDB, tokenHash []byte, userID int64, expires time.Time) error {
	_, err := q.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expires)
	return err
}

// SessionUser returns the user owning a non-expired session.
func SessionUser(ctx context.Context, q AuthDB, tokenHash []byte) (AuthUser, error) {
	return scanAuthUser(q.QueryRow(ctx,
		`SELECT `+authUserCols+` FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 JOIN roles r ON r.id = u.role_id
		 WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash))
}

// DeleteSession removes one session.
func DeleteSession(ctx context.Context, q AuthDB, tokenHash []byte) error {
	_, err := q.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUserSessions removes all sessions of a user (e.g. after a role change).
func DeleteUserSessions(ctx context.Context, q AuthDB, userID int64) error {
	_, err := q.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// DeleteExpiredSessions removes expired sessions.
func DeleteExpiredSessions(ctx context.Context, q AuthDB) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return tag.RowsAffected(), err
}

// ListRoles returns roles with permissions and user counts, built-ins first.
func ListRoles(ctx context.Context, q AuthDB) ([]AuthRole, error) {
	rows, err := q.Query(ctx, `SELECT r.id, r.name, r.builtin,
		COALESCE((SELECT array_agg(rp.perm ORDER BY rp.perm) FROM role_permissions rp WHERE rp.role_id = r.id), '{}'),
		(SELECT count(*) FROM users u WHERE u.role_id = r.id)
		FROM roles r ORDER BY r.builtin DESC, r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthRole
	for rows.Next() {
		var r AuthRole
		if err := rows.Scan(&r.ID, &r.Name, &r.Builtin, &r.Perms, &r.Users); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RolePerms returns the permissions of a role.
func RolePerms(ctx context.Context, q AuthDB, roleID int64) ([]string, error) {
	var perms []string
	err := q.QueryRow(ctx,
		`SELECT COALESCE(array_agg(perm ORDER BY perm), '{}') FROM role_permissions WHERE role_id = $1`,
		roleID).Scan(&perms)
	return perms, err
}

// CreateRole inserts a custom role with permissions. Call it inside a
// transaction so a failed permission insert does not leave an empty role.
func CreateRole(ctx context.Context, q AuthDB, name string, perms []string) (int64, error) {
	var id int64
	if err := q.QueryRow(ctx,
		`INSERT INTO roles (name, builtin) VALUES ($1, false) RETURNING id`, name).Scan(&id); err != nil {
		return 0, err
	}
	if len(perms) > 0 {
		if _, err := q.Exec(ctx,
			`INSERT INTO role_permissions (role_id, perm) SELECT $1, unnest($2::text[])`,
			id, perms); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// DeleteRole deletes a non-built-in role that no user has.
func DeleteRole(ctx context.Context, q AuthDB, id int64) (string, error) {
	var (
		name    string
		builtin bool
		users   int
	)
	err := q.QueryRow(ctx, `SELECT name, builtin, (SELECT count(*) FROM users WHERE role_id = $1)
		FROM roles WHERE id = $1`, id).Scan(&name, &builtin, &users)
	if err != nil {
		return "", err
	}
	if builtin {
		return name, ErrRoleBuiltin
	}
	if users > 0 {
		return name, ErrRoleInUse
	}
	_, err = q.Exec(ctx, `DELETE FROM roles WHERE id = $1 AND NOT builtin`, id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // user assigned concurrently
		return name, ErrRoleInUse
	}
	return name, err
}

// InsertAudit appends an audit_log entry. userID may be nil (e.g. failed login).
func InsertAudit(ctx context.Context, q AuthDB, userID *int64, action, entity string, details any) error {
	if details == nil {
		details = map[string]any{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx,
		`INSERT INTO audit_log (user_id, action, entity, details) VALUES ($1, $2, $3, $4)`,
		userID, action, entity, b)
	return err
}

// ListAudit returns the most recent audit entries.
func ListAudit(ctx context.Context, q AuthDB, limit int) ([]AuditEntry, error) {
	rows, err := q.Query(ctx, `SELECT a.id, a.at, a.user_id, COALESCE(u.login, ''), a.action, a.entity, a.details::text
		FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
		ORDER BY a.at DESC, a.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.Login, &e.Action, &e.Entity, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PutSecretEnc upserts an already encrypted secret.
func PutSecretEnc(ctx context.Context, q AuthDB, name string, enc []byte) error {
	_, err := q.Exec(ctx, `INSERT INTO secrets (name, value_enc) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET value_enc = EXCLUDED.value_enc`, name, enc)
	return err
}

// GetSecretEnc returns an encrypted secret; pgx.ErrNoRows when absent.
func GetSecretEnc(ctx context.Context, q AuthDB, name string) ([]byte, error) {
	var enc []byte
	err := q.QueryRow(ctx, `SELECT value_enc FROM secrets WHERE name = $1`, name).Scan(&enc)
	return enc, err
}
