#!/usr/bin/env python3
"""
build_sr.py — emit a self-contained Shadowrocket config from the iplist-mirror snapshot.

Reproduces the proven "ip-list proxy" layout: one [Rule] section grouped per
service, each block = a `# slug (category)` comment, then all DOMAIN-SUFFIX
rules (-> PROXY), then all IP-CIDR / IP-CIDR6 rules (-> PROXY, no-resolve).
Everything inlined — domains AND the exact RU-subtracted CIDR set — so routing
is as precise as the catalog allows. The proxy itself comes from the user's
VLESS subscription (PROXY policy); no [Proxy] server is embedded.

Source of truth: ../snapshot-ru-clean.json  (services: slug, category, domains,
cidr4, cidr6 — RU-allocated ranges already subtracted).

Output: split.conf  (self-contained; blocked services -> PROXY, FINAL DIRECT)
        blocked-services.list  (flat IP-CIDR set, kept for the RULE-SET variant)

Usage: python3 sr/build_sr.py   (run from repo root or sr/)
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP = os.path.join(HERE, "..", "snapshot-ru-clean.json")
OUT_CONF = os.path.join(HERE, "split.conf")
OUT_LIST = os.path.join(HERE, "blocked-services.list")
UPDATE_URL = "https://raw.githubusercontent.com/baklaki52/iplist-mirror/main/sr/split.conf"

snap = json.load(open(SNAP))
services = snap.get("services", [])
if not services:
    sys.exit(f"{SNAP}: no services")

GENERAL = """# Shadowrocket — SPLIT (self-contained, ip-list proxy)
# Per-service: DOMAIN-SUFFIX -> PROXY, then exact RU-subtracted IP-CIDR -> PROXY.
# Прокси берётся из VLESS-подписки (политика PROXY). Своего [Proxy] тут нет.
# Add by URL: Config -> "+" -> Download from URL. Auto-updates via update-url.
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
# Шифрованный DNS (Cloudflare + Google, DoH/DoT) — провайдер (МГТС и т.п.) не видит
# и не подменяет запросы, заблокированные домены резолвятся честно. НЕ системный.
dns-server = https://security.cloudflare-dns.com/dns-query,tls://1.1.1.2,tls://1.0.0.2,https://dns.google/dns-query,tls://8.8.8.8,tls://8.8.4.4
fallback-dns-server = tls://77.88.8.88,77.88.8.88,system
ipv6 = true
prefer-ipv6 = false
dns-direct-system = false
dns-fallback-system = false
dns-direct-fallback-proxy = true
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
udp-policy-not-supported-behaviour = REJECT
update-url = %s

[Rule]
""" % UPDATE_URL

lines = [GENERAL.rstrip("\n")]
all_cidrs, seen_cidr = [], set()
n_dom = n_v4 = n_v6 = 0

for svc in sorted(services, key=lambda s: (s.get("category", ""), s.get("slug", ""))):
    slug = svc.get("slug", "")
    cat = svc.get("category", "")
    domains = sorted(set(d.strip() for d in svc.get("domains", []) if d.strip()))
    v4 = [c.strip() for c in svc.get("cidr4", []) if c.strip()]
    v6 = [c.strip() for c in svc.get("cidr6", []) if c.strip()]
    if not (domains or v4 or v6):
        continue
    lines.append("")
    lines.append(f"# {slug} ({cat})")
    for d in domains:
        lines.append(f"DOMAIN-SUFFIX,{d},PROXY")
        n_dom += 1
    for c in v4:
        lines.append(f"IP-CIDR,{c},PROXY,no-resolve")
        n_v4 += 1
        if c not in seen_cidr:
            seen_cidr.add(c); all_cidrs.append(c)
    for c in v6:
        lines.append(f"IP-CIDR6,{c},PROXY,no-resolve")
        n_v6 += 1
        if c not in seen_cidr:
            seen_cidr.add(c); all_cidrs.append(c)

# tail: LAN direct, default direct, host map
lines += [
    "",
    "# LAN",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,172.16.0.0/12,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT",
    "",
    "FINAL,DIRECT",
    "",
    "[Host]",
    "localhost = 127.0.0.1",
    "",
]
open(OUT_CONF, "w").write("\n".join(lines))

# flat list (RULE-SET variant), deduped
hdr = [
    "# blocked-services.list — flat RU-subtracted CIDR set from snapshot-ru-clean.json",
    f"# {len(all_cidrs)} CIDRs",
    "# Policy + no-resolve come from the RULE-SET reference in the .conf",
]
body = [f"IP-CIDR6,{c}" if ":" in c else f"IP-CIDR,{c}" for c in all_cidrs]
open(OUT_LIST, "w").write("\n".join(hdr + body) + "\n")

print(f"split.conf: {n_dom} domains + {n_v4} v4 + {n_v6} v6 across "
      f"{sum(1 for s in services if s.get('domains') or s.get('cidr4') or s.get('cidr6'))} services")
print(f"blocked-services.list: {len(all_cidrs)} unique CIDRs")
