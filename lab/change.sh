#!/usr/bin/env bash
# Switch the lab to a variant: ./change.sh run1|run2|run3   (also: ./change.sh down)
# Applies compose.yml + variants/<run>.yml; services not in the variant are removed
# (--remove-orphans) and scale: 0 services are stopped. Idempotent. Returns once every service in
# expected/<run>.json accepts TCP connections (exit 1 if that takes longer than LAB_WAIT seconds).
set -euo pipefail
cd "$(dirname "$0")"
run="${1:-}"
case "$run" in
  run1|run2|run3) ;;
  down) exec docker compose -f compose.yml down -v --remove-orphans ;;
  *) echo "usage: $0 run1|run2|run3|down" >&2; exit 2 ;;
esac
docker compose -f compose.yml -f "variants/$run.yml" up -d --build --remove-orphans >&2
echo "$run" > .current-run
# Wait until every TCP service listed in expected/<run>.json accepts connections (Jenkins, MySQL and
# Tomcat need 20-60 s after a cold start), so a scan started right after this script sees them all.
# Probed from the scanner container, inside the lab network only. LAB_WAIT=0 skips, default 180 s.
wait_s="${LAB_WAIT:-180}"
if [ "$wait_s" -gt 0 ]; then
  targets=$(tr -d ' \n' < "expected/$run.json" | sed 's/"changes_from_prev".*//' \
    | grep -o '"ip":"[0-9.]*"\|"port":[0-9]*' | awk -F: '
        /"ip"/ { gsub(/"/, "", $2); ip = $2; next }
        { print ip ":" $2 }')
  if ! docker exec -e T="$targets" -e W="$wait_s" asi-lab-scanner-1 sh -c '
      end=$(( $(date +%s) + W ))
      while :; do
        miss=""
        for t in $T; do nc -z -w 1 "${t%:*}" "${t#*:}" 2>/dev/null || miss="$miss $t"; done
        [ -z "$miss" ] && exit 0
        [ "$(date +%s)" -ge "$end" ] && { echo "not ready after ${W}s:$miss" >&2; exit 1; }
        sleep 2
      done'; then
    echo "WARNING: some expected services are not reachable yet (see above)" >&2
    exit 1
  fi
fi
docker compose -f compose.yml -f "variants/$run.yml" ps --format '{{.Service}}\t{{.State}}' | sort
