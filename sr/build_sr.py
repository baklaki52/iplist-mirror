#!/usr/bin/env python3
"""
build_sr.py — emit Shadowrocket RULE-SET list from the iplist-mirror snapshot.

Source of truth is the repo's RU-subtracted flat CIDR list, NOT a server file:
    all-cidrs-ru-clean.json  (full catalog of all blocked services, minus
                              RU-allocated ranges so Russian traffic goes direct)

Unlike AmneziaWG AllowedIPs (capped by the iOS NetworkExtension memory limit),
a Shadowrocket RULE-SET is fetched by URL and matched rule-by-rule — no route
table, no memory cap. So we ship the FULL, most precise set, not a subset.

Output: blocked-services.list  (IP-CIDR / IP-CIDR6 lines, no policy — the
        policy + no-resolve come from the RULE-SET reference in the .conf)

Usage:
    python3 build_sr.py [source.json] [out.list]
Defaults: ../all-cidrs-ru-clean.json -> blocked-services.list
Run from the sr/ directory (or pass explicit paths).
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "all-cidrs-ru-clean.json")
out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "blocked-services.list")

cidrs = json.load(open(src))
if not isinstance(cidrs, list):
    sys.exit(f"{src}: expected a JSON array of CIDRs")

# dedup, preserve order
seen, ordered = set(), []
for c in cidrs:
    c = (c or "").strip()
    if c and c not in seen:
        seen.add(c); ordered.append(c)

v4 = sum(1 for c in ordered if ":" not in c)
v6 = sum(1 for c in ordered if ":" in c)
header = [
    "# blocked-services.list — full RU-subtracted CIDR set from iplist-mirror",
    "# Source: all-cidrs-ru-clean.json (all blocked services, minus RU-allocated)",
    f"# {len(ordered)} CIDRs ({v4} v4 + {v6} v6)",
    "# Policy + no-resolve come from the RULE-SET reference in the .conf",
]
body = [f"IP-CIDR6,{c}" if ":" in c else f"IP-CIDR,{c}" for c in ordered]
open(out, "w").write("\n".join(header + body) + "\n")
print(f"wrote {out}: {len(body)} rules ({v4} v4 + {v6} v6)")
