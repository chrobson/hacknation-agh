-- 0001_init.sql: core schema contract. FROZEN after the W0 commit.
-- Module migrations use their own ranges: 0100-0199 targets, 0200 scan,
-- 0300 fingerprint, 0400 diff, 0500 auth, 0600 dojo/export.
-- All tables use the database default access method (tde_heap via pg_tde).

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

-- Auth / RBAC --------------------------------------------------------------
CREATE TABLE roles (
    id      bigserial PRIMARY KEY,
    name    text NOT NULL UNIQUE,
    builtin boolean NOT NULL DEFAULT false
);

CREATE TABLE role_permissions (
    role_id bigint NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    perm    text   NOT NULL,
    PRIMARY KEY (role_id, perm)
);

CREATE TABLE users (
    id         bigserial PRIMARY KEY,
    login      text NOT NULL UNIQUE,
    pass_hash  text NOT NULL,
    role_id    bigint NOT NULL REFERENCES roles(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Built-in roles (names match the task statement) and their permissions.
INSERT INTO roles (name, builtin) VALUES
    ('Administracja', true),
    ('Dodawanie, usuwanie, modyfikacja', true),
    ('Modyfikacja i odczyt', true),
    ('Odczyt', true);

INSERT INTO role_permissions (role_id, perm)
SELECT r.id, p.perm FROM roles r
JOIN (VALUES
    ('Administracja', 'targets.read'), ('Administracja', 'targets.write'),
    ('Administracja', 'scans.run'), ('Administracja', 'results.read'),
    ('Administracja', 'results.edit'), ('Administracja', 'signatures.write'),
    ('Administracja', 'export'), ('Administracja', 'users.admin'),
    ('Dodawanie, usuwanie, modyfikacja', 'targets.read'),
    ('Dodawanie, usuwanie, modyfikacja', 'targets.write'),
    ('Dodawanie, usuwanie, modyfikacja', 'scans.run'),
    ('Dodawanie, usuwanie, modyfikacja', 'results.read'),
    ('Dodawanie, usuwanie, modyfikacja', 'results.edit'),
    ('Dodawanie, usuwanie, modyfikacja', 'signatures.write'),
    ('Dodawanie, usuwanie, modyfikacja', 'export'),
    ('Modyfikacja i odczyt', 'targets.read'),
    ('Modyfikacja i odczyt', 'results.read'),
    ('Modyfikacja i odczyt', 'results.edit'),
    ('Modyfikacja i odczyt', 'export'),
    ('Odczyt', 'targets.read'),
    ('Odczyt', 'results.read')
) AS p(role, perm) ON p.role = r.name;

-- Targets and scan configuration --------------------------------------------
CREATE TABLE targets (
    id         bigserial PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
    value      text NOT NULL UNIQUE,
    tags       text[] NOT NULL DEFAULT '{}',
    created_by bigint REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scan_configs (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    target_ids    bigint[] NOT NULL DEFAULT '{}',
    top_ports     int NOT NULL DEFAULT 1000,
    max_rate      int NOT NULL DEFAULT 1000,  -- packets/s for the whole run, split R/K across workers
    workers       int NOT NULL DEFAULT 4,
    window_start  time,                        -- NULL = no window
    window_end    time,                        -- may be < window_start (window crosses midnight)
    every_minutes int,                         -- NULL = manual only
    enabled       boolean NOT NULL DEFAULT true
);

CREATE TABLE scan_runs (
    id          bigserial PRIMARY KEY,
    config_id   bigint REFERENCES scan_configs(id),
    kind        text NOT NULL DEFAULT 'scan' CHECK (kind IN ('scan', 'import')),
    status      text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'paused', 'done', 'failed')),
    started_at  timestamptz,
    finished_at timestamptz,
    duration_ms bigint
);

-- Work queue: leased with SELECT ... FOR UPDATE SKIP LOCKED.
-- On startup the runner resets status 'running' -> 'pending'.
CREATE TABLE scan_chunks (
    id          bigserial PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    cidr        cidr   NOT NULL,
    status      text   NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'done', 'failed')),
    attempts    int    NOT NULL DEFAULT 0,
    started_at  timestamptz,
    duration_ms bigint,
    hosts_up    int
);
CREATE INDEX scan_chunks_queue ON scan_chunks (run_id, status);

-- Observations -----------------------------------------------------------------
CREATE TABLE host_obs (
    run_id   bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip       inet   NOT NULL,
    hostname text   NOT NULL DEFAULT '',
    up       boolean NOT NULL,
    PRIMARY KEY (run_id, ip)
);

CREATE TABLE host_state (
    ip         inet PRIMARY KEY,
    state      text NOT NULL CHECK (state IN ('up', 'down', 'inactive', 'unstable')),
    misses     int  NOT NULL DEFAULT 0,
    flips      jsonb NOT NULL DEFAULT '[]',   -- last N up/down observations: [{"run":1,"up":true},...]
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE services (
    id        bigserial PRIMARY KEY,
    run_id    bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip        inet   NOT NULL,
    port      int    NOT NULL,
    proto     text   NOT NULL,
    vhost     text   NOT NULL DEFAULT '',
    product   text   NOT NULL DEFAULT '',
    version   text   NOT NULL DEFAULT '',
    extrainfo text   NOT NULL DEFAULT '',
    cpe       text   NOT NULL DEFAULT '',
    banner    text   NOT NULL DEFAULT '',
    UNIQUE (run_id, ip, port, proto, vhost)
);

CREATE TABLE http_obs (
    service_id   bigint PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
    url          text NOT NULL,
    status       int,
    title        text NOT NULL DEFAULT '',
    headers      jsonb NOT NULL DEFAULT '{}',
    cookies      jsonb NOT NULL DEFAULT '[]',
    redirects    jsonb NOT NULL DEFAULT '[]',
    tls          jsonb,
    favicon_mmh3 int,
    body_sha256  text NOT NULL DEFAULT ''
);

CREATE TABLE signatures (
    id      text PRIMARY KEY,          -- stable slug, e.g. 'wordpress'
    name    text NOT NULL,
    yaml    text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    builtin boolean NOT NULL DEFAULT false
);

CREATE TABLE detections (
    service_id   bigint NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    signature_id text   NOT NULL,
    name         text   NOT NULL,
    category     text   NOT NULL,    -- cms|framework|server|iot|admin-panel|staging|other
    confidence   int    NOT NULL,    -- 0-100
    evidence     jsonb  NOT NULL DEFAULT '{}',
    PRIMARY KEY (service_id, signature_id)
);

-- Analyst edits keyed by the natural asset key: survive rescans.
CREATE TABLE annotations (
    ip             inet NOT NULL,
    port           int  NOT NULL DEFAULT 0,     -- 0 = host-level annotation
    proto          text NOT NULL DEFAULT '',
    vhost          text NOT NULL DEFAULT '',
    comment        text NOT NULL DEFAULT '',
    tags           text[] NOT NULL DEFAULT '{}',
    severity       text,
    false_positive boolean NOT NULL DEFAULT false,
    updated_by     bigint REFERENCES users(id),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ip, port, proto, vhost)
);

CREATE TABLE changes (
    id          bigserial PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    prev_run_id bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    kind        text NOT NULL CHECK (kind IN ('new', 'gone', 'changed', 'host_up', 'host_down', 'unstable')),
    ip          inet NOT NULL,
    port        int  NOT NULL DEFAULT 0,
    proto       text NOT NULL DEFAULT '',
    vhost       text NOT NULL DEFAULT '',
    field       text NOT NULL DEFAULT '',
    old         text NOT NULL DEFAULT '',
    new         text NOT NULL DEFAULT ''
);
CREATE INDEX changes_run ON changes (run_id);

-- Application secrets (e.g. DefectDojo API token), AES-GCM encrypted by the app.
CREATE TABLE secrets (
    name      text PRIMARY KEY,
    value_enc bytea NOT NULL
);

CREATE TABLE audit_log (
    id      bigserial PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    user_id bigint REFERENCES users(id),
    action  text  NOT NULL,
    entity  text  NOT NULL DEFAULT '',
    details jsonb NOT NULL DEFAULT '{}'
);

-- pg_statistic is NOT encrypted by pg_tde: after ANALYZE it would hold
-- most_common_vals/histograms of these columns in clear text. Disable stats.
ALTER TABLE host_obs   ALTER COLUMN ip SET STATISTICS 0, ALTER COLUMN hostname SET STATISTICS 0;
ALTER TABLE host_state ALTER COLUMN ip SET STATISTICS 0;
ALTER TABLE services   ALTER COLUMN ip SET STATISTICS 0, ALTER COLUMN banner SET STATISTICS 0,
                       ALTER COLUMN product SET STATISTICS 0, ALTER COLUMN version SET STATISTICS 0;
ALTER TABLE http_obs   ALTER COLUMN url SET STATISTICS 0, ALTER COLUMN title SET STATISTICS 0;
ALTER TABLE targets    ALTER COLUMN value SET STATISTICS 0;
ALTER TABLE annotations ALTER COLUMN ip SET STATISTICS 0, ALTER COLUMN comment SET STATISTICS 0;
ALTER TABLE changes    ALTER COLUMN ip SET STATISTICS 0, ALTER COLUMN old SET STATISTICS 0, ALTER COLUMN new SET STATISTICS 0;
