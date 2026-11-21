#!/usr/bin/env bash
# End-to-end test against the docker scan lab (10.20.0.0/18 only).
#   scripts/e2e.sh smoke   lab run1: import targets, scan, asi verify
#   scripts/e2e.sh full    run1 -> run2 -> run3 with change detection and the
#                          unstable host, RBAC (viewer gets 403 on POST),
#                          DefectDojo Generic Findings export validated offline
#                          and re-imported, pg_tde encryption checks.
# nmap runs only inside the app container attached to the lab network.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-smoke}"
case "$mode" in smoke|full) ;; *) echo "usage: $0 smoke|full" >&2; exit 2 ;; esac

export ASI_PORT="${ASI_PORT:-18080}"
PROJECT="${E2E_PROJECT:-asi-e2e}"
DC=(docker compose -p "$PROJECT" -f compose.yml -f compose.lab.yml)
BASE="http://127.0.0.1:${ASI_PORT}"
MIN="${E2E_MIN:-0.9}"
OUT="tmp/e2e"
mkdir -p "$OUT"

log() { printf '\n=== %s\n' "$*" >&2; }
fail() { echo "E2E FAIL: $*" >&2; exit 1; }
asi() { "${DC[@]}" exec -T app asi "$@"; }
put() { "${DC[@]}" exec -T app sh -c "cat > $2" < "$1"; }   # host file -> container path
psql_db() { "${DC[@]}" exec -T db psql -U "${ASI_DB_USER:-asi}" -d asi -tAX -v ON_ERROR_STOP=1 -c "$1"; }

[ -f .env ] || ./scripts/gen-env.sh
set -a; . ./.env; set +a

log "lab variant run1"
lab/change.sh run1 >/dev/null

log "fresh app + database ($PROJECT) attached to the lab network"
"${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${DC[@]}" up -d --build --wait db app
curl -fsS "$BASE/healthz" >/dev/null || fail "app not healthy"

log "import targets (lab CIDR + vhost)"
printf 'value,tags\n10.20.0.0/18,lab\nstaging.lab.local,lab;vhost\n' > "$OUT/targets.csv"
put "$OUT/targets.csv" /tmp/targets.csv
asi import /tmp/targets.csv | tee "$OUT/import.json"
grep -q '"imported": 2' "$OUT/import.json" || fail "target import"

for f in lab/expected/run1.json lab/expected/run2.json lab/expected/run3.json; do
  put "$f" "/tmp/$(basename "$f")"
done

scan_and_verify() {
  local run="$1"
  log "scan ($run)"
  asi scan | tee "$OUT/scan_$run.json"
  grep -q '"status":"done"' "$OUT/scan_$run.json" || fail "scan $run not done"
  log "verify ($run)"
  if ! asi verify "/tmp/$run.json" -min "$MIN" > "$OUT/verify_$run.json"; then
    cat "$OUT/verify_$run.json"; fail "verify $run"
  fi
  python3 - "$OUT/verify_$run.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
def f(m):
    t = f" top1000={m['recall_top1000']}" if m.get('recall_top1000') is not None else ""
    return f"P={m['precision']} R={m['recall']}{t} (tp={m['tp']} fp={m['fp']} fn={m['fn']})"
print(f"run {r['run_id']} vs {r['expected']}: duration_ms={r.get('duration_ms')}")
for k in ("hosts", "services", "detections", "changes"):
    print(f"  {k:<10} {f(r[k])}")
    if r[k].get('missing'): print(f"    missing: {r[k]['missing']}")
    if r[k].get('unexpected'): print(f"    unexpected: {r[k]['unexpected'][:15]}")
PY
}

scan_and_verify run1

log "dashboard as admin"
JAR="$OUT/admin.jar"
rm -f "$JAR"
curl -fsS -c "$JAR" -b "$JAR" -o /dev/null -d "login=admin" --data-urlencode "password=${ASI_SEED_PASSWORD_ADMIN}" "$BASE/login"
curl -fsS -b "$JAR" "$BASE/" > "$OUT/dashboard.html"
grep -q "Pulpit" "$OUT/dashboard.html" || fail "dashboard"
for p in /targets /scans /results /changes /host-states /signatures /export /admin/users; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE$p")
  [ "$code" = 200 ] || fail "GET $p as admin -> $code"
done

if [ "$mode" = smoke ]; then
  log "SMOKE OK"
  exit 0
fi

for run in run2 run3; do
  log "lab variant $run"
  lab/change.sh "$run" >/dev/null
  scan_and_verify "$run"
done

log "unstable host after run3"
python3 - "$OUT/verify_run3.json" <<'PY' || fail "unstable host not reported"
import json, sys
r = json.load(open(sys.argv[1]))
assert "unstable 10.20.60.120" not in r["changes"].get("missing", []), r["changes"]
PY
[ "$(psql_db "SELECT state FROM host_state WHERE ip='10.20.60.120'")" = unstable ] || fail "10.20.60.120 not unstable"

log "RBAC: viewer gets 403 on a POST"
VJAR="$OUT/viewer.jar"
rm -f "$VJAR"
curl -fsS -c "$VJAR" -b "$VJAR" -o /dev/null -d "login=viewer" --data-urlencode "password=${ASI_SEED_PASSWORD_VIEWER}" "$BASE/login"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$VJAR" -d "values=10.20.1.1" "$BASE/targets")
[ "$code" = 403 ] || fail "viewer POST /targets -> $code (want 403)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$VJAR" -d "name=x" "$BASE/scans")
[ "$code" = 403 ] || fail "viewer POST /scans -> $code (want 403)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$VJAR" "$BASE/results")
[ "$code" = 200 ] || fail "viewer GET /results -> $code (want 200)"

log "DefectDojo Generic Findings: export, offline validation, re-import"
asi export dojo > "$OUT/findings.json"
asi validate-dojo /dev/stdin < "$OUT/findings.json" || fail "Generic Findings validation"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d['findings']), 'findings')" "$OUT/findings.json"
asi export csv > "$OUT/services.csv"
asi export json > "$OUT/services.json"
put "$OUT/findings.json" /tmp/findings.json
asi import /tmp/findings.json | tee "$OUT/reimport.json"
grep -q '"format": "generic"' "$OUT/reimport.json" || grep -q '"run_id"' "$OUT/reimport.json" || fail "re-import"

log "import semantics: a re-import of our own export reports no false changes"
RID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['run_id'])" "$OUT/reimport.json")
psql_db "SELECT kind, count(*) FROM changes WHERE run_id=$RID GROUP BY kind ORDER BY kind"
bad=$(psql_db "SELECT count(*) FROM changes WHERE run_id=$RID AND kind IN ('gone','changed','host_down')")
[ "$bad" = 0 ] || fail "re-import produced $bad gone/changed/host_down rows"

log "import semantics: a 1-host import leaves other hosts alone"
python3 - "$OUT/findings.json" "$OUT/one-host.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
first = d["findings"][0]["endpoints"][0]["host"]
d["findings"] = [f for f in d["findings"] if f["endpoints"][0]["host"] == first]
json.dump(d, open(sys.argv[2], "w"))
PY
down_before=$(psql_db "SELECT count(*) FROM host_state WHERE state <> 'up'")
put "$OUT/one-host.json" /tmp/one-host.json
asi import /tmp/one-host.json > "$OUT/one-host-import.json"
RID1=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['run_id'])" "$OUT/one-host-import.json")
bad=$(psql_db "SELECT count(*) FROM changes WHERE run_id=$RID1 AND kind IN ('gone','host_down')")
down_after=$(psql_db "SELECT count(*) FROM host_state WHERE state <> 'up'")
echo "1-host import: gone/host_down=$bad, hosts not up before=$down_before after=$down_after"
[ "$bad" = 0 ] && [ "$down_before" = "$down_after" ] || fail "partial import changed other hosts"

log "RBAC: analyst (export, no scans.run) gets 403 on POST /import"
AJAR="$OUT/analyst.jar"
rm -f "$AJAR"
curl -fsS -c "$AJAR" -b "$AJAR" -o /dev/null -d "login=analyst" --data-urlencode "password=${ASI_SEED_PASSWORD_ANALYST}" "$BASE/login"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$AJAR" -H "Origin: $BASE" -F "file=@$OUT/one-host.json" "$BASE/import")
[ "$code" = 403 ] || fail "analyst POST /import -> $code (want 403)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$AJAR" "$BASE/export/services.csv")
[ "$code" = 200 ] || fail "analyst GET /export/services.csv -> $code (want 200)"

log "pg_tde: every table encrypted"
plain=$(psql_db "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public' AND c.relkind IN ('r','m') AND NOT pg_tde_is_encrypted(c.oid::regclass)")
total=$(psql_db "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','m')")
echo "tables: $total, not encrypted: $plain"
[ "$plain" = 0 ] && [ "$total" -gt 10 ] || fail "unencrypted tables: $plain"

log "pg_statistic: no samples of text, JSON or address columns"
psql_db "ANALYZE" >/dev/null
stats=$(psql_db "SELECT count(*) FROM pg_statistic s JOIN pg_class c ON c.oid=s.starelid
  JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=s.staattnum
  WHERE n.nspname='public' AND a.atttypid IN ('text'::regtype,'varchar'::regtype,'jsonb'::regtype,'json'::regtype,
    'inet'::regtype,'cidr'::regtype,'bytea'::regtype,'text[]'::regtype)")
echo "pg_statistic rows for sensitive columns: $stats"
[ "$stats" = 0 ] || fail "pg_statistic holds samples of $stats sensitive columns"

log "pg_tde: marker not visible on disk after CHECKPOINT"
MARK="ASIE2E$(openssl rand -hex 12)"
psql_db "INSERT INTO annotations (ip, port, proto, vhost, comment) VALUES ('10.20.0.10', 80, 'tcp', '', '$MARK')
  ON CONFLICT (ip, port, proto, vhost) DO UPDATE SET comment = EXCLUDED.comment" >/dev/null
psql_db "CHECKPOINT" >/dev/null
psql_db "SELECT pg_switch_wal()" >/dev/null
hits=$("${DC[@]}" exec -T db sh -c "grep -rlF '$MARK' /data/db 2>/dev/null | wc -l" | tr -d ' ')
echo "files containing the marker: $hits"
[ "$hits" = 0 ] || fail "plaintext marker found on disk"

log "E2E FULL OK"
