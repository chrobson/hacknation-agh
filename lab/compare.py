#!/usr/bin/env python3
"""Compare real nmap XML (testdata/nmap/<run>_*.xml) with lab/expected/<run>.json. Stdlib only.

    python3 lab/compare.py run1 [run2 ...]

Checks: live hosts from discovery == expected hosts + infra; every expected in_top1000 service is
found open in the services scan with the same product/version; no unexpected open ports.
Exit 1 on any mismatch.
"""
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def ipv4(h):
    return next(a.get("addr") for a in h.findall("address") if a.get("addrtype") == "ipv4")


def check(run):
    exp = json.loads((ROOT / "lab/expected" / f"{run}.json").read_text())
    disc = ET.parse(ROOT / "testdata/nmap" / f"{run}_discovery.xml").getroot()
    serv = ET.parse(ROOT / "testdata/nmap" / f"{run}_services.xml").getroot()
    errs = []
    live = {ipv4(h) for h in disc.findall("host") if h.find("status").get("state") == "up"}
    want = {h["ip"] for h in exp["hosts"]} | {i["ip"] for i in exp["infra"]}
    for ip in sorted(want - live):
        errs.append(f"discovery: missing host {ip}")
    for ip in sorted(live - want):
        errs.append(f"discovery: unexpected host {ip}")
    got = {}
    for h in serv.findall("host"):
        for p in h.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            s = p.find("service")
            got[(ipv4(h), int(p.get("portid")), p.get("protocol"))] = (
                (s.get("product", ""), s.get("version", "")) if s is not None else ("", ""))
    want_s = {}
    for h in exp["hosts"]:
        for s in h["services"]:
            if s["in_top1000"]:
                want_s[(h["ip"], s["port"], s["proto"])] = (s["product"], s["version"])
    for k in sorted(want_s):
        if k not in got:
            errs.append(f"services: missing {k}")
        elif got[k] != want_s[k]:
            errs.append(f"services: {k} product/version {got[k]} != expected {want_s[k]}")
    for k in sorted(set(got) - set(want_s)):
        errs.append(f"services: unexpected open {k} {got[k]}")
    fin = lambda r: r.find("runstats/finished").get("elapsed")
    print(f"{run}: live={len(live)} services={len(got)} expected_services={len(want_s)} "
          f"discovery={fin(disc)}s services_scan={fin(serv)}s -> {'OK' if not errs else 'MISMATCH'}")
    for e in errs:
        print("  " + e)
    return not errs


if __name__ == "__main__":
    ok = all([check(r) for r in (sys.argv[1:] or ["run1"])])
    sys.exit(0 if ok else 1)
