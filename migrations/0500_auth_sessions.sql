-- 0500_auth_sessions.sql: server-side sessions for internal/auth.
-- The cookie carries a random token; only its SHA-256 is stored, so a
-- database dump does not yield usable session cookies.
CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE INDEX audit_log_at ON audit_log (at DESC);

-- pg_statistic is not encrypted by pg_tde: keep logins and audit details out of it.
ALTER TABLE users     ALTER COLUMN login SET STATISTICS 0;
ALTER TABLE audit_log ALTER COLUMN details SET STATISTICS 0;
