-- 0300_fp.sql: fingerprint module (W1-3). Uses the default access method
-- (tde_heap), so the table and its index are encrypted by pg_tde.

-- Result of the explicit TLS 1.0 / 1.1 handshake probe per HTTPS service.
CREATE TABLE IF NOT EXISTS tls_legacy (
    service_id   bigint PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
    tls10        boolean NOT NULL DEFAULT false,
    tls11        boolean NOT NULL DEFAULT false,
    tls10_cipher text    NOT NULL DEFAULT '',
    tls11_cipher text    NOT NULL DEFAULT '',
    probed_at    timestamptz NOT NULL DEFAULT now()
);

-- Detections are listed per signature in the UI and in exports.
CREATE INDEX IF NOT EXISTS detections_signature ON detections (signature_id);

-- Header values and certificate details can identify hosts: keep them out of
-- the unencrypted pg_statistic catalog.
ALTER TABLE http_obs ALTER COLUMN headers SET STATISTICS 0,
                     ALTER COLUMN tls SET STATISTICS 0,
                     ALTER COLUMN redirects SET STATISTICS 0;
ALTER TABLE detections ALTER COLUMN evidence SET STATISTICS 0;
