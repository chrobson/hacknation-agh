#!/usr/bin/env bash
# Run the two-phase reference scan from the scanner container and save raw nmap XML.
#   ./scan.sh run1   -> ../testdata/nmap/run1_discovery.xml, run1_services.xml
# Phase 1: host discovery (root: ICMP echo + TCP SYN/ACK pings; on this L2 segment nmap uses ARP).
# Phase 2: SYN scan of top 1000 ports with light version detection on live hosts only.
# Infra addresses are excluded from phase 2: scanner (10.20.63.250), gateway (10.20.0.1) and the
# network address 10.20.0.0, which the docker bridge answers on ARP.
# Usage with the app attached to the lab network: LAB_EXCLUDE=10.20.63.251 ./scan.sh run1
set -euo pipefail
cd "$(dirname "$0")"
run="${1:?usage: $0 run1|run2|run3}"
out=../testdata/nmap
mkdir -p "$out"
S="docker exec asi-lab-scanner-1"
# LAB_EXCLUDE: extra non-target addresses attached to the lab network (comma separated), e.g. the
# application container at 10.20.63.251. They are left out of both phases so the saved XML holds
# lab targets only.
excl="${LAB_EXCLUDE:-}"
t0=$(date +%s)
$S nmap -sn -n -PE -PS21,22,23,25,53,80,110,143,443,445,1883,3306,3389,5432,8080,8443 -PA80,443 \
  ${excl:+--exclude "$excl"} 10.20.0.0/18 -oX - > "$out/${run}_discovery.xml"
t1=$(date +%s)
live=$(grep -o 'addr="10\.20\.[0-9.]*" addrtype="ipv4"' "$out/${run}_discovery.xml" | cut -d'"' -f2 \
  | grep -v -x -e 10.20.63.250 -e 10.20.0.1 -e 10.20.0.0 | tr '\n' ' ')
echo "phase1: $((t1-t0))s, live targets: $(echo $live | wc -w)" >&2
$S nmap -sS -n -Pn --top-ports 1000 -sV --version-light --open $live -oX - > "$out/${run}_services.xml"
t2=$(date +%s)
echo "phase2: $((t2-t1))s" >&2
echo "${run} discovery=$((t1-t0))s services=$((t2-t1))s hosts=$(echo $live | wc -w)"
