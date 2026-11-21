-- 0810_http_response_ms.sql: HTTP response time per probe (first request to
-- the service: connect, TLS, headers and body), shown in the UI and compared
-- between runs. NULL = not measured (older rows, imports). An integer column
-- carries no host data, so it keeps the default statistics target.
ALTER TABLE http_obs ADD COLUMN IF NOT EXISTS response_ms int;
