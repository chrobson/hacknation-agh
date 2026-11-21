-- 0800_port_profile.sql: port profile of a scan configuration.
--   auto  all 65535 TCP ports (-p-) when the targets total at most
--         ASI_ALL_PORTS_MAX_ADDRS addresses (default 16), otherwise top
--   top   --top-ports N plus the extra pass (extra_ports, extra_port_list)
--   list  the explicit list in ports (-p)
--   all   all 65535 TCP ports (-p-)
ALTER TABLE scan_configs ADD COLUMN IF NOT EXISTS port_profile text NOT NULL DEFAULT 'auto';
ALTER TABLE scan_configs DROP CONSTRAINT IF EXISTS scan_configs_port_profile_check;
ALTER TABLE scan_configs ADD CONSTRAINT scan_configs_port_profile_check
    CHECK (port_profile IN ('auto', 'top', 'list', 'all'));
-- Additional TCP ports scanned in the extra pass of the top profile.
ALTER TABLE scan_configs ADD COLUMN IF NOT EXISTS extra_port_list text NOT NULL DEFAULT '';

-- Configurations saved with an explicit list keep scanning exactly that list.
UPDATE scan_configs SET port_profile = 'list' WHERE ports <> '' AND port_profile = 'auto';

-- Text columns stay out of pg_statistic (see 0700_hardening.sql).
ALTER TABLE scan_configs ALTER COLUMN port_profile SET STATISTICS 0;
ALTER TABLE scan_configs ALTER COLUMN extra_port_list SET STATISTICS 0;
