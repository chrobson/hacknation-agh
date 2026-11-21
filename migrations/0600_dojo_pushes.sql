-- 0600_dojo_pushes.sql: history of DefectDojo pushes (W1-6, range 0600-0699).
-- Uses the database default access method (tde_heap via pg_tde).
CREATE TABLE dojo_pushes (
    id          bigserial PRIMARY KEY,
    run_id      bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    pushed_at   timestamptz NOT NULL DEFAULT now(),
    endpoint    text   NOT NULL DEFAULT '',     -- import-scan | reimport-scan
    findings    int    NOT NULL DEFAULT 0,
    test_id     bigint,
    ok          boolean NOT NULL,
    error       text   NOT NULL DEFAULT '',
    statistics  jsonb  NOT NULL DEFAULT '{}'
);
CREATE INDEX dojo_pushes_at ON dojo_pushes (pushed_at DESC);
