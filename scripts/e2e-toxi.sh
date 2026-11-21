#!/usr/bin/env bash
# Fault-injection e2e: do degraded-but-alive services produce false changes?
#
# Stack: ci/agh-proxy.yml (stand-in for the AGH "modern-proxy" template:
# WordPress behind Traefik behind Toxiproxy). Ports scanned: web (Traefik,
# proxied WordPress), dashboard (Traefik API) and the Toxiproxy API.
#
#   run1  baseline
#   run2  latency toxic on the WordPress proxy (800 ms, jitter 200 ms)
#   run3  latency + timeout toxic (connections dropped after TOXI_TIMEOUT_MS)
#   run4  toxics removed, the toxiproxy service stopped for real
#
# Asserts: run2 and run3 contain 0 'gone' and 0 'changed' rows for the three
# services, except field response_ms (the response time change is the true
# signal of the injected delay and is reported on purpose, see
# internal/diff/latency.go). run4 contains exactly one 'gone': the Toxiproxy
# API port. Every change row is written to tmp/e2e-toxi/changes.txt.
#
# Modes (E2E_TOXI_MODE): host (Linux default: app in the host network
# namespace, target localhost), hostgw (macOS default: target
# host.docker.internal), native (asi + nmap on this host).
# Host ports of the stack: TOXI_WEB_PORT/TOXI_DASH_PORT/TOXI_API_PORT
# (default 8085/8086/8474), so it can run next to another copy.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '\n=== %s\n' "$*" >&2; }
fail() { echo "E2E-TOXI FAIL: $*" >&2; exit 1; }

export TOXI_WEB_PORT="${TOXI_WEB_PORT:-8085}" TOXI_DASH_PORT="${TOXI_DASH_PORT:-8086}" TOXI_API_PORT="${TOXI_API_PORT:-8474}"
export TOXI_PROJECT="${TOXI_PROJECT:-asi-toxi-lab}"
export ASI_PORT="${ASI_PORT:-18082}" ASI_DB_PORT="${ASI_DB_PORT:-55434}"
LATENCY_MS="${TOXI_LATENCY_MS:-800}" JITTER_MS="${TOXI_JITTER_MS:-200}" TIMEOUT_MS="${TOXI_TIMEOUT_MS:-1000}"
ports=("$TOXI_WEB_PORT" "$TOXI_DASH_PORT" "$TOXI_API_PORT")
portlist="$(IFS=,; echo "${ports[*]}")"
out="tmp/e2e-toxi"
mkdir -p "$out"
: > "$out/changes.txt"

amode="${E2E_TOXI_MODE:-}"
if [ -z "$amode" ]; then
  case "$(uname -s)" in Linux) amode=host ;; *) amode=hostgw ;; esac
fi
project="${E2E_PROJECT:-asi-toxi}"
case "$amode" in
  hostgw) DC=(docker compose -p "$project" -f compose.yml -f compose.hostgw.yml); target=host.docker.internal ;;
  host|native) DC=(docker compose -p "$project" -f compose.host.yml); target=localhost ;;
  *) fail "E2E_TOXI_MODE must be hostgw, host or native" ;;
esac
LAB=(docker compose -f ci/agh-proxy.yml)
api="http://127.0.0.1:${TOXI_API_PORT}"

[ -f .env ] || ./scripts/gen-env.sh
set -a; . ./.env; set +a
psql_db() { "${DC[@]}" exec -T db psql -U "${ASI_DB_USER:-asi}" -d asi -tAX -v ON_ERROR_STOP=1 -c "$1"; }
if [ "$amode" = native ]; then
  command -v nmap >/dev/null || fail "native mode needs nmap on this host"
  go build -trimpath -o bin/asi ./cmd/asi
  asi() {
    ASI_DATABASE_URL="postgres://${ASI_DB_USER:-asi}:${ASI_DB_PASSWORD}@127.0.0.1:${ASI_DB_PORT}/asi?sslmode=disable" ./bin/asi "$@"
  }
  put() { cp "$1" "$2"; }
else
  asi() { "${DC[@]}" exec -T app asi "$@"; }
  put() { "${DC[@]}" exec -T app sh -c "cat > $2" < "$1"; }
fi

wait_port() { # wait_port <port> open|closed
  local i
  for i in $(seq 1 120); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
      [ "$2" = open ] && return 0
    else
      [ "$2" = closed ] && return 0
    fi
    sleep 1
  done
  return 1
}
teardown() {
  log "tear down"
  "${LAB[@]}" down -v >/dev/null 2>&1 || true
  [ "${E2E_KEEP:-0}" = 1 ] || "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT

log "proxy lab up (web $TOXI_WEB_PORT, dashboard $TOXI_DASH_PORT, toxiproxy API $TOXI_API_PORT)"
"${LAB[@]}" up -d --wait mariadb
"${LAB[@]}" up -d
for p in "${ports[@]}"; do wait_port "$p" open || fail "lab port $p not open"; done
for _ in $(seq 1 60); do curl -fs "$api/version" >/dev/null && break; sleep 1; done
curl -fsS -X DELETE "$api/proxies/wordpress" >/dev/null 2>&1 || true
curl -fsS -X POST "$api/proxies" -H 'Content-Type: application/json' \
  -d '{"name":"wordpress","listen":"0.0.0.0:8666","upstream":"wordpress:80"}' >/dev/null || fail "create proxy"
code=""
for _ in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${TOXI_WEB_PORT}/" || true)
  case "$code" in 2*|3*) break ;; esac
  sleep 2
done
case "$code" in 2*|3*) ;; *) fail "WordPress behind the proxy not answering (HTTP $code)" ;; esac
sleep "${E2E_TOXI_SETTLE:-5}"

log "fresh app + database ($project, mode $amode, target $target)"
"${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
if [ "$amode" = native ]; then
  "${DC[@]}" up -d --wait db
  asi migrate >/dev/null
else
  "${DC[@]}" up -d --build --wait db app
fi
printf 'value,tags\n%s,toxi\n' "$target" > "$out/targets.csv"
put "$out/targets.csv" /tmp/asi-toxi-targets.csv
asi import /tmp/asi-toxi-targets.csv > "$out/import.json"
grep -q '"imported": 1' "$out/import.json" || fail "target import"
psql_db "INSERT INTO scan_configs (name, target_ids, max_rate, workers, port_profile, ports)
         VALUES ('toxi', '{}', ${E2E_TOXI_RATE:-2000}, 2, 'list', '$portlist')" >/dev/null

ip=""
scan() { # scan <name> -> run id
  log "scan ($1)"
  local t0=$SECONDS
  asi scan toxi > "$out/scan_$1.json"
  grep -q '"status":"done"' "$out/scan_$1.json" || { cat "$out/scan_$1.json" >&2; fail "scan $1 not done"; }
  echo "scan $1: $((SECONDS - t0)) s" >&2
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['run_id'])" "$out/scan_$1.json"
}
show() { # show <run> <label>: services and change rows of a run
  {
    echo "--- $2 (run $1): services"
    psql_db "SELECT port, coalesce(nullif(product,''),'-'), coalesce(nullif(version,''),'-'), left(coalesce(banner,''),40)
             FROM services WHERE run_id=$1 AND ip='$ip' AND vhost='' ORDER BY port"
    echo "--- $2 (run $1): changes"
    psql_db "SELECT kind, port, coalesce(field,''), left(coalesce(old,''),50) || ' -> ' || left(coalesce(new,''),50)
             FROM changes WHERE run_id=$1 AND ip='$ip' ORDER BY kind, port, field"
  } | tee -a "$out/changes.txt" >&2
}
# Counted for the first IPv4 address of the target only: on Linux "localhost"
# also resolves to ::1, which is a second host with its own (identical) rows.
count() { psql_db "SELECT count(*) FROM changes WHERE run_id=$1 AND ip='$ip' AND $2"; }
toxic() { # toxic <json>
  curl -fsS -X POST "$api/proxies/wordpress/toxics" -H 'Content-Type: application/json' -d "$1" >/dev/null || fail "toxic $1"
}

r1=$(scan run1-baseline)
ip=$(psql_db "SELECT host(ip) FROM host_obs WHERE run_id=$r1 AND up AND family(ip)=4 ORDER BY ip LIMIT 1")
[ -n "$ip" ] || fail "run1: target not up"
show "$r1" baseline
for p in "${ports[@]}"; do
  [ "$(psql_db "SELECT count(*) FROM services WHERE run_id=$r1 AND ip='$ip' AND vhost='' AND port=$p")" -ge 1 ] || fail "run1: port $p not found"
done

log "toxic: latency ${LATENCY_MS} ms +- ${JITTER_MS} ms (downstream)"
toxic "{\"name\":\"lat\",\"type\":\"latency\",\"stream\":\"downstream\",\"attributes\":{\"latency\":$LATENCY_MS,\"jitter\":$JITTER_MS}}"
echo "web with latency: $(curl -s -o /dev/null -w '%{http_code} %{time_total}s' --max-time 20 "http://127.0.0.1:${TOXI_WEB_PORT}/")" >&2
r2=$(scan run2-latency)
show "$r2" latency

log "toxic: timeout ${TIMEOUT_MS} ms (downstream) on top of latency"
toxic "{\"name\":\"to\",\"type\":\"timeout\",\"stream\":\"downstream\",\"attributes\":{\"timeout\":$TIMEOUT_MS}}"
echo "web with timeout: $(curl -s -o /dev/null -w '%{http_code} %{time_total}s' --max-time 20 "http://127.0.0.1:${TOXI_WEB_PORT}/")" >&2
r3=$(scan run3-timeout)
show "$r3" latency+timeout

bad=0
for r in "$r2" "$r3"; do
  g=$(count "$r" "kind='gone'")
  c=$(count "$r" "kind='changed' AND coalesce(field,'') <> 'response_ms'")
  l=$(count "$r" "kind='changed' AND field = 'response_ms'")
  echo "run $r: false gone=$g, false changed=$c, response_ms changed=$l (expected signal)" | tee -a "$out/summary.txt" >&2
  [ "$g" = 0 ] && [ "$c" = 0 ] || bad=1
done

log "remove toxics, stop the toxiproxy service (true gone of port $TOXI_API_PORT)"
curl -fsS -X DELETE "$api/proxies/wordpress/toxics/to" >/dev/null || true
curl -fsS -X DELETE "$api/proxies/wordpress/toxics/lat" >/dev/null || true
"${LAB[@]}" stop toxiproxy
wait_port "$TOXI_API_PORT" closed || fail "toxiproxy API still open"
r4=$(scan run4-stopped)
show "$r4" stopped
g4=$(count "$r4" "kind='gone'")
g4api=$(count "$r4" "kind='gone' AND port=$TOXI_API_PORT")
echo "run $r4: gone=$g4 (port $TOXI_API_PORT: $g4api)" | tee -a "$out/summary.txt" >&2

[ "$bad" = 0 ] || fail "false gone/changed under toxics (see $out/changes.txt)"
[ "$g4" = 1 ] && [ "$g4api" = 1 ] || fail "run4: want exactly one gone ($TOXI_API_PORT), got $g4"
log "E2E TOXI OK (mode $amode): 0 false gone/changed under latency and timeout, 1 true gone after stop"
