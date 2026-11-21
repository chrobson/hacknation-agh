-- 0100_targets.sql: indexes for the targets module (tde_heap compatible:
-- plain btree/GIN indexes, encrypted together with the table by pg_tde).

-- Tag filter on the targets list (tags && ARRAY['lab']).
CREATE INDEX IF NOT EXISTS targets_tags_gin ON targets USING gin (tags);

-- Tags may carry customer names; keep them out of the unencrypted pg_statistic.
ALTER TABLE targets ALTER COLUMN tags SET STATISTICS 0;
