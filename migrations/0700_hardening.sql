-- A run stopped by a user stays stopped: the scheduler does not resume it
-- until a user resumes it explicitly.
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS stopped boolean NOT NULL DEFAULT false;

-- Explicit TCP port list per scan config (replaces --top-ports when set) and
-- a switch for the second pass over common infrastructure ports.
ALTER TABLE scan_configs ADD COLUMN IF NOT EXISTS ports text NOT NULL DEFAULT '';
ALTER TABLE scan_configs ADD COLUMN IF NOT EXISTS extra_ports boolean NOT NULL DEFAULT true;

-- pg_statistic is a catalog outside pg_tde: ANALYZE would copy plaintext
-- samples (most common values, histograms) of every column into it. Turn
-- statistics off for every text-like column of the application tables and
-- drop the samples collected so far.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.relname, a.attname
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
          AND a.attnum > 0 AND NOT a.attisdropped
          AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'jsonb'::regtype, 'json'::regtype,
                             'inet'::regtype, 'cidr'::regtype, 'bytea'::regtype, 'text[]'::regtype)
    LOOP
        EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET STATISTICS 0', r.relname, r.attname);
    END LOOP;
    BEGIN
        DELETE FROM pg_statistic s
        USING pg_class c, pg_namespace n
        WHERE s.starelid = c.oid AND c.relnamespace = n.oid AND n.nspname = current_schema();
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'pg_statistic not cleared (not a superuser); run ANALYZE after granting';
    END;
END $$;

ANALYZE;
