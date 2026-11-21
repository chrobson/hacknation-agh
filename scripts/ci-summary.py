#!/usr/bin/env python3
"""Markdown summary of an e2e-agh output directory (GitHub step summary)."""
import json
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "tmp/e2e-agh"
print("### asi verify (run3), ubuntu-24.04, host network, target localhost")
print("```")
try:
    r = json.load(open(os.path.join(out, "verify_run3.json")))
    for m in ("hosts", "services", "detections", "changes"):
        x = r[m]
        print(f"{m:10s} P={x['precision']} R={x['recall']} tp={x['tp']} fp={x['fp']} fn={x['fn']}")
    print("pass", r["pass"])
except (OSError, ValueError, KeyError) as e:
    print("no verify result:", e)
print("```")
for name, title in (("changes.txt", "changes (run2: 8787 stopped, run3: restored)"),
                    ("services_run3.txt", "template services in run3 (nmap -sV)")):
    print(f"### {title}")
    print("```")
    try:
        print(open(os.path.join(out, name)).read().rstrip())
    except OSError:
        print("(missing)")
    print("```")
