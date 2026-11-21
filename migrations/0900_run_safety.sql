-- 0900_run_safety.sql: per-run safety receipt. What the scan actually sent,
-- measured by the scanner itself: nmap packets (nmap's own "Raw packets
-- sent" counter under -v, plus connect() probes estimated from the XML) and
-- elapsed time, HTTP requests per method, requests carrying credentials,
-- the peak HTTP rate over a 1 s sliding window, and every scanned address
-- re-checked against the allowlist after the run. Writes are best-effort:
-- a failed write never fails a scan. A resumed run adds to its row.
CREATE TABLE IF NOT EXISTS run_safety (
    run_id                    bigint PRIMARY KEY REFERENCES scan_runs (id) ON DELETE CASCADE,
    nmap_invocations          int    NOT NULL DEFAULT 0,
    nmap_raw_reported         int    NOT NULL DEFAULT 0,
    nmap_packets              bigint NOT NULL DEFAULT 0,
    nmap_elapsed_ms           bigint NOT NULL DEFAULT 0,
    nmap_busy_ms              bigint NOT NULL DEFAULT 0,
    nmap_peak_invocation_pps  real   NOT NULL DEFAULT 0,
    configured_max_rate       int    NOT NULL DEFAULT 0,
    per_worker_rate           int    NOT NULL DEFAULT 0,
    argv_sha256               text   NOT NULL DEFAULT '',
    argv_sample               text[] NOT NULL DEFAULT '{}',
    http_get                  int    NOT NULL DEFAULT 0,
    http_head                 int    NOT NULL DEFAULT 0,
    http_other                int    NOT NULL DEFAULT 0,
    http_auth_headers         int    NOT NULL DEFAULT 0,
    http_peak_rps             real   NOT NULL DEFAULT 0,
    http_rate_limit           real   NOT NULL DEFAULT 0,
    http_burst                int    NOT NULL DEFAULT 0,
    targets_checked           bigint NOT NULL DEFAULT 0,
    targets_outside_allowlist bigint NOT NULL DEFAULT 0,
    updated_at                timestamptz NOT NULL DEFAULT now()
);

-- argv_sample contains scanned addresses: keep it out of pg_statistic
-- (outside pg_tde), like every other text column (see 0700_hardening.sql).
ALTER TABLE run_safety ALTER COLUMN argv_sha256 SET STATISTICS 0;
ALTER TABLE run_safety ALTER COLUMN argv_sample SET STATISTICS 0;
