-- 0200_scan.sql: scan runner additions (W1-2). Plain tables/indexes only, so
-- they use the database default access method (tde_heap).

-- Last error of a chunk (interruption reason or nmap failure), shown in the UI.
ALTER TABLE scan_chunks ADD COLUMN IF NOT EXISTS last_error text NOT NULL DEFAULT '';
-- Error messages may contain addresses: keep them out of pg_statistic.
ALTER TABLE scan_chunks ALTER COLUMN last_error SET STATISTICS 0;
ALTER TABLE scan_chunks ALTER COLUMN cidr SET STATISTICS 0;

-- Leasing: SELECT ... WHERE run_id=$1 AND status='pending' ORDER BY id FOR UPDATE SKIP LOCKED.
CREATE INDEX IF NOT EXISTS scan_chunks_pending ON scan_chunks (run_id, id) WHERE status = 'pending';

-- Scheduler: latest run per config and open runs.
CREATE INDEX IF NOT EXISTS scan_runs_config ON scan_runs (config_id, id DESC);
CREATE INDEX IF NOT EXISTS scan_runs_open ON scan_runs (status) WHERE status IN ('queued', 'running', 'paused');
