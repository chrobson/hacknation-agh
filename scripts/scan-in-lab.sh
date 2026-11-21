#!/usr/bin/env bash
# Live check of internal/scan against the docker lab, executed INSIDE the lab
# scanner container (asi-lab-scanner-1, network 10.20.0.0/18). nmap never runs
# on the host: we cross-compile the lab-tagged test binary, copy it into the
# container and run it there.
#
#   scripts/scan-in-lab.sh               # scans 10.20.0.0/24
#   ASI_LAB_PREFIX=10.20.1.0/24 scripts/scan-in-lab.sh
set -euo pipefail
cd "$(dirname "$0")/.."

C="${ASI_LAB_SCANNER:-asi-lab-scanner-1}"
PREFIX="${ASI_LAB_PREFIX:-10.20.0.0/24}"

case "$PREFIX" in
  10.20.*) ;;
  *) echo "refusing: $PREFIX is outside the lab network 10.20.0.0/18" >&2; exit 2 ;;
esac

if ! docker ps --format '{{.Names}}' | grep -qx "$C"; then
  echo "lab scanner container $C is not running (cd lab && ./change.sh run1)" >&2
  exit 1
fi

case "$(docker exec "$C" uname -m)" in
  aarch64|arm64) arch=arm64 ;;
  x86_64|amd64)  arch=amd64 ;;
  *) echo "unsupported container arch" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -tags lab -o "$tmp/scan.test" ./internal/scan
docker cp "$tmp/scan.test" "$C:/tmp/asi-scan.test" >/dev/null
docker exec -e ASI_LAB_SCAN=1 -e ASI_LAB_PREFIX="$PREFIX" "$C" \
  /tmp/asi-scan.test -test.run 'TestLabLive' -test.v -test.timeout 10m
docker exec "$C" rm -f /tmp/asi-scan.test
