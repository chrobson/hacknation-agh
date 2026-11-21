-- 0400_diff.sql: diff bookkeeping (W1-4). Uses the default access method (tde_heap).

-- One row per run whose diff and host-state update have been applied; makes
-- applying a run idempotent and records which run it was compared against.
CREATE TABLE diff_runs (
    run_id      bigint PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
    prev_run_id bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    changes     int NOT NULL DEFAULT 0,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX changes_key ON changes (ip, port, proto, vhost);
