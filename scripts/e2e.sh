#!/usr/bin/env bash
# End-to-end test against the docker scan lab (10.20.0.0/18 only).
#   scripts/e2e.sh smoke   lab run1: import targets, scan, asi verify
#   scripts/e2e.sh full    run1 -> run2 -> run3 with change detection and the
#                          unstable host, RBAC (viewer gets 403 on POST),
#                          DefectDojo Generic Findings export validated offline
#                          and re-imported, pg_tde encryption checks.
#   scripts/e2e.sh agh-template
#                          AGH custom-network template on localhost (see
#                          agh_template below): scan, stop the service on
#                          8787, rescan, restore, rescan (gone, new,
#                          unstable), asi verify of run3.
# In smoke/full nmap runs only inside the app container attached to the lab
# network.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-smoke}"
case "$mode" in smoke|full|agh-template) ;; *) echo "usage: $0 smoke|full|agh-template" >&2; exit 2 ;; esac

log() { printf '\n=== %s\n' "$*" >&2; }
fail() { echo "E2E FAIL: $*" >&2; exit 1; }

# agh_template runs the quickstart scenario of the AGH lab template
# (docker-compose-custom-network.yml: httpbin 8888, PostgreSQL 15432,
# RabbitMQ 5673/15673, Gitea 3001/2223, nginx 8787) against services
# published on this host. The template files are not part of this repository
# (unknown licence): ASI_AGH_LAB_DIR points at them (default notes/lab-agh of
# the main checkout). The app reaches the host in one of three modes
# (E2E_AGH_MODE):
#   hostgw  app container -> host.docker.internal (default on macOS)
#   host    app container in the host network namespace -> localhost (default on Linux)
#   native  asi binary and nmap on this host -> localhost; database in docker
agh_template() {
  local dir="${ASI_AGH_LAB_DIR:-notes/lab-agh}"
  if [ ! -f "$dir/docker-compose-custom-network.yml" ]; then
    # A git worktree has no notes/: fall back to the main checkout.
    local main
    main="$(cd "$(git rev-parse --path-format=absolute --git-common-dir)/.." && pwd)"
    dir="$main/notes/lab-agh"
  fi
  local tplfile="$dir/docker-compose-custom-network.yml"
  [ -f "$tplfile" ] || fail "AGH template not found: set ASI_AGH_LAB_DIR (docker-compose-custom-network.yml)"
  local amode="${E2E_AGH_MODE:-}"
  if [ -z "$amode" ]; then
    case "$(uname -s)" in Linux) amode=host ;; *) amode=hostgw ;; esac
  fi
  export ASI_PORT="${ASI_PORT:-18081}" ASI_DB_PORT="${ASI_DB_PORT:-55433}"
  local project="${E2E_PROJECT:-asi-agh}" target out="tmp/e2e-agh" ip
  # Global (not local): the EXIT trap runs after this function has returned.
  TPL=(docker compose -f "$tplfile")
  case "$amode" in
    hostgw) DC=(docker compose -p "$project" -f compose.yml -f compose.hostgw.yml); target=host.docker.internal ;;
    host|native) DC=(docker compose -p "$project" -f compose.yml -f compose.host.yml); target=localhost ;;
    *) fail "E2E_AGH_MODE must be hostgw, host or native" ;;
  esac
  target="${E2E_AGH_TARGET:-$target}"
  mkdir -p "$out"
  [ -f .env ] || ./scripts/gen-env.sh
  set -a; . ./.env; set +a
  if [ "$target" = localhost ] && [ -n "${ASI_ALLOWED_CIDRS:-}" ]; then
    case ",${ASI_ALLOWED_CIDRS// /}," in
      *,127.0.0.0/8,*) ;;
      *) fail ".env sets ASI_ALLOWED_CIDRS without 127.0.0.0/8 (and ::1/128): localhost would be rejected" ;;
    esac
  fi
  psql_db() { "${DC[@]}" exec -T db psql -U "${ASI_DB_USER:-asi}" -d asi -tAX -v ON_ERROR_STOP=1 -c "$1"; }
  if [ "$amode" = native ]; then
    command -v nmap >/dev/null || fail "native mode needs nmap on this host"
    go build -trimpath -o bin/asi ./cmd/asi
    asi() {
      ASI_DATABASE_URL="postgres://${ASI_DB_USER:-asi}:${ASI_DB_PASSWORD}@127.0.0.1:${ASI_DB_PORT}/asi?sslmode=disable" \
        ./bin/asi "$@"
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
    log "tear down the AGH template stack"
    "${TPL[@]}" down -v >/dev/null 2>&1 || true
    if [ "${E2E_KEEP:-0}" != 1 ]; then
      "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
  }
  trap teardown EXIT

  log "AGH template up ($tplfile)"
  "${TPL[@]}" up -d
  for port in 8787 8888 15432 5673 15673 3001 2223; do
    wait_port "$port" open || fail "template port $port not open"
  done
  # Gitea and RabbitMQ accept connections before they answer; give -sV a
  # chance to see the same banner in every run.
  sleep "${E2E_AGH_SETTLE:-15}"

  log "fresh app + database ($project, mode $amode, target $target)"
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "$amode" = native ]; then
    "${DC[@]}" up -d --wait db
    asi migrate >/dev/null
  else
    "${DC[@]}" up -d --build --wait db app
    curl -fsS "http://127.0.0.1:${ASI_PORT}/healthz" >/dev/null || fail "app not healthy"
  fi

  log "import target $target"
  printf 'value,tags\n%s,agh\n' "$target" > "$out/targets.csv"
  put "$out/targets.csv" /tmp/asi-agh-targets.csv
  asi import /tmp/asi-agh-targets.csv | tee "$out/import.json"
  grep -q '"imported": 1' "$out/import.json" || fail "target import"
  # Default port profile (auto): one or two addresses -> all 65535 ports.
  psql_db "INSERT INTO scan_configs (name, target_ids, max_rate, workers) VALUES ('agh-template', '{}', ${E2E_AGH_RATE:-5000}, 4)" >/dev/null

  ports_of() { # ports_of <run> -> sorted open TCP ports of the target address
    psql_db "SELECT string_agg(port::text, ' ' ORDER BY port) FROM services WHERE run_id=$1 AND ip='$ip' AND vhost='' AND proto='tcp'"
  }
  scan() { # scan <name> -> run id
    log "scan ($1)"
    asi scan agh-template | tee "$out/scan_$1.json" >&2
    grep -q '"status":"done"' "$out/scan_$1.json" || fail "scan $1 not done"
    python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['run_id'])" "$out/scan_$1.json"
  }
  has() { case " $1 " in *" $2 "*) return 0 ;; esac; return 1; }
  want=(8888 15432 5673 15673 3001 2223)

  r1=$(scan run1)
  ip=$(psql_db "SELECT host(ip) FROM host_obs WHERE run_id=$r1 AND up AND family(ip)=4 ORDER BY ip LIMIT 1")
  [ -n "$ip" ] || fail "run1: target host not up"
  p1=$(ports_of "$r1")
  echo "run1 $ip: $p1"
  for p in "${want[@]}" 8787; do has "$p1" "$p" || fail "run1: port $p not detected on $ip"; done

  log "stop the service on 8787 (flask-app)"
  "${TPL[@]}" stop flask-app
  wait_port 8787 closed || fail "8787 still open after stop"
  r2=$(scan run2)
  p2=$(ports_of "$r2")
  echo "run2 $ip: $p2"
  has "$p2" 8787 && fail "run2: 8787 still reported"
  for p in "${want[@]}"; do has "$p2" "$p" || fail "run2: port $p missing on $ip"; done
  [ "$(psql_db "SELECT count(*) FROM changes WHERE run_id=$r2 AND kind='gone' AND ip='$ip' AND port=8787")" = 1 ] \
    || fail "run2: no 'gone' change for $ip:8787"

  log "restore the service on 8787"
  "${TPL[@]}" up -d flask-app
  wait_port 8787 open || fail "8787 not back"
  r3=$(scan run3)
  p3=$(ports_of "$r3")
  echo "run3 $ip: $p3"
  for p in "${want[@]}" 8787; do has "$p3" "$p" || fail "run3: port $p missing on $ip"; done
  [ "$(psql_db "SELECT count(*) FROM changes WHERE run_id=$r3 AND kind='new' AND ip='$ip' AND port=8787")" = 1 ] \
    || fail "run3: no 'new' change for $ip:8787"
  # Two flips (gone, back) within ASI_UNSTABLE_WINDOW make the service
  # unstable (ASI_UNSTABLE_IF_FLIPS=2); the host itself stays up.
  [ "$(psql_db "SELECT count(*) FROM changes WHERE run_id=$r3 AND kind='unstable' AND ip='$ip' AND port=8787")" = 1 ] \
    || fail "run3: no 'unstable' change for $ip:8787"
  [ "$(psql_db "SELECT state FROM host_state WHERE ip='$ip'")" = up ] || fail "host $ip not up"

  log "asi verify run3 against the expected state"
  # Expected state: the template ports with their detections, plus the other
  # ports of this host seen in all three runs (services outside the template
  # that run on this machine); changes: 8787 back and unstable.
  python3 - "$ip" "$p1" "$p2" "$p3" > "$out/expected_run3.json" <<'PY'
import json, sys
ip, runs = sys.argv[1], [set(map(int, a.split())) for a in sys.argv[2:5]]
tpl = {8787: [], 8888: ["httpbin"], 15432: ["postgresql"], 5673: ["rabbitmq-amqp"],
       15673: ["rabbitmq-management"], 3001: ["gitea"], 2223: []}
other = (runs[0] & runs[1] & runs[2]) - set(tpl)
svcs = [{"port": p, "proto": "tcp", "in_top1000": True, "detections": d} for p, d in sorted(tpl.items())]
svcs += [{"port": p, "proto": "tcp", "in_top1000": False, "detections": []} for p in sorted(other)]
print(json.dumps({"run": "agh-run3", "network": ip + "/32", "infra": [],
    "hosts": [{"ip": ip, "name": "docker-host", "services": svcs}],
    "changes_from_prev": [{"kind": k, "ip": ip, "port": 8787, "proto": "tcp", "in_top1000": True}
                          for k in ("new", "unstable")]}))
PY
  put "$out/expected_run3.json" /tmp/asi-agh-expected.json
  asi verify /tmp/asi-agh-expected.json -run "$r3" -min 0.9 > "$out/verify_run3.json" || true
  python3 - "$out/verify_run3.json" <<'PY' || fail "asi verify run3"
import json, sys
r = json.load(open(sys.argv[1]))
for m in ("hosts", "services", "detections", "changes"):
    x = r[m]
    print(f"  {m:10s} P={x['precision']} R={x['recall']} (tp={x['tp']} fp={x['fp']} fn={x['fn']})"
          + (f" missing={x['missing']}" if x.get("missing") else "") + (f" unexpected={x['unexpected']}" if x.get("unexpected") else ""))
assert r["pass"], r.get("failures")
assert r["changes"]["recall"] == 1, r["changes"]
assert r["detections"]["recall"] == 1, r["detections"]
PY

  log "changes per run (target $ip)"
  psql_db "SELECT run_id, kind, port, field, left(coalesce(nullif(new,''),old), 60) FROM changes
    WHERE run_id IN ($r2,$r3) AND ip='$ip' AND port IN (0,8787,8888,15432,5673,15673,3001,2223) ORDER BY run_id, kind, port" | tee "$out/changes.txt"
  echo "host_state $ip: $(psql_db "SELECT state FROM host_state WHERE ip='$ip'")"
  log "template services in run3 (nmap -sV)"
  psql_db "SELECT port, product, version FROM services WHERE run_id=$r3 AND ip='$ip' AND vhost=''
    AND port IN (8787,8888,15432,5673,15673,3001,2223) ORDER BY port" | tee "$out/services_run3.txt"

  if [ "$amode" != native ]; then
    log "scans page shows the port profile"
    local jar="$out/admin.jar" base="http://127.0.0.1:${ASI_PORT}"
    rm -f "$jar"
    curl -fsS -c "$jar" -b "$jar" -o /dev/null -d "login=admin" --data-urlencode "password=${ASI_SEED_PASSWORD_ADMIN}" "$base/login"
    curl -fsS -b "$jar" "$base/scans" | grep -q -- "-p-" || fail "/scans does not show the port profile"
    curl -fsS -b "$jar" "$base/scans/new" | grep -q 'name="port_profile"' || fail "/scans/new has no port profile field"
  fi
  log "E2E AGH-TEMPLATE OK (mode $amode: run1 $r1, run2 $r2 without 8787, run3 $r3 with 8787)"
}

if [ "$mode" = agh-template ]; then
  agh_template
  exit 0
fi

export ASI_PORT="${ASI_PORT:-18080}"
PROJECT="${E2E_PROJECT:-asi-e2e}"
DC=(docker compose -p "$PROJECT" -f compose.yml -f compose.lab.yml)
BASE="http://127.0.0.1:${ASI_PORT}"
MIN="${E2E_MIN:-0.9}"
OUT="tmp/e2e"
mkdir -p "$OUT"

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
