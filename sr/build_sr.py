#!/usr/bin/env python3
"""
build_sr.py — emit Shadowrocket RULE-SET list from the same CIDR source AmneziaWG uses.

Input : allowed_ips_ordered.json  (per-service popularity-ranked CIDR array,
        produced by awg-bot/fetch_lists.py -> build_ordered()). This is the exact
        set AmneziaWG puts in AllowedIPs, so SR routing stays identical to AWG.
Output: blocked-services.list      (IP-CIDR / IP-CIDR6 lines, no policy —
        the policy + no-resolve come from the RULE-SET reference in the .conf)

The .conf files (split.conf, clean.conf) are server-agnostic static templates:
they carry NO server, only routing. The proxy comes from the user's VLESS
subscription and is referenced via the PROXY policy. One set of configs works
for any server (baton, kvn, ...) — only the subscription differs.

Usage:
    python3 build_sr.py [ordered.json] [out.list]
Defaults: allowed_ips_ordered.json -> blocked-services.list
"""
import json, sys

src = sys.argv[1] if len(sys.argv) > 1 else "allowed_ips_ordered.json"
out = sys.argv[2] if len(sys.argv) > 2 else "blocked-services.list"

cidrs = json.load(open(src))
if not isinstance(cidrs, list):
    sys.exit(f"{src}: expected a JSON array of CIDRs")

v4 = sum(1 for c in cidrs if ":" not in c)
v6 = sum(1 for c in cidrs if ":" in c)
header = [
    "# blocked-services.list — IP-CIDR set, identical to AmneziaWG AllowedIPs",
    "# Source: iplist-mirror snapshot -> allowed_ips_ordered.json (per-service popularity-ranked)",
    f"# {len(cidrs)} CIDRs ({v4} v4 + {v6} v6)",
    "# Policy + no-resolve come from the RULE-SET reference in the .conf",
]
body = [f"IP-CIDR6,{c.strip()}" if ":" in c else f"IP-CIDR,{c.strip()}"
        for c in cidrs if c.strip()]
open(out, "w").write("\n".join(header + body) + "\n")
print(f"wrote {out}: {len(body)} rules ({v4} v4 + {v6} v6)")
