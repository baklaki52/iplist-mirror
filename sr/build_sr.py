#!/usr/bin/env python3
"""
build_sr.py — emit self-contained Shadowrocket configs from the iplist-mirror snapshot.

Layout ("ip-list proxy"): one [Rule] section grouped per service — a
`# slug (category)` comment, then DOMAIN-SUFFIX rules (-> PROXY), then the exact
RU-subtracted IP-CIDR / IP-CIDR6 rules (-> PROXY, no-resolve). Everything inlined.
The proxy itself comes from the user's VLESS subscription (PROXY policy); no
[Proxy] server is embedded, so one config works for any server.

Two outputs, identical routing, different DNS:
  split.conf          — PUBLIC (lives on GitHub): Cloudflare/Google DoH, no secrets.
  split-private.conf  — PRIVATE (secret gist, share with friends only): our DoH
                        (dnsdist->unbound on baton) as primary, Cloudflare fallback.

Source of truth: ../snapshot-ru-clean.json (services: slug, category, domains,
cidr4, cidr6 — RU-allocated ranges already subtracted).
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP = os.path.join(HERE, "..", "snapshot-ru-clean.json")

# our DoH endpoint (token is a path secret; kept out of the public repo).
# Goes via the rus relay (dns.telescope.cv -> 85.204.240.39 -> baton:8443) so it
# resolves & connects from RU home/mobile nets where baton's own IP is throttled.
OUR_DOH = "https://dns.telescope.cv:8853/340ff56150a3b88f/dns-query"

DNS_PUBLIC = """# Шифрованный DNS (Cloudflare + Google DoH/DoT) — провайдер не видит/не подменяет.
dns-server = https://security.cloudflare-dns.com/dns-query,tls://1.1.1.2,tls://1.0.0.2,https://dns.google/dns-query,tls://8.8.8.8
fallback-dns-server = tls://77.88.8.88,77.88.8.88,system"""

DNS_PRIVATE = """# Наш DoH (unbound на baton, анти-деанон) — DNS на нашем IP. Fallback Cloudflare/Google.
dns-server = %s
fallback-dns-server = https://security.cloudflare-dns.com/dns-query,tls://1.1.1.2,https://dns.google/dns-query,system""" % OUR_DOH


def general(title, dns_block, update_url):
    return f"""# Shadowrocket — {title}
# Per-service: DOMAIN-SUFFIX -> PROXY, then exact RU-subtracted IP-CIDR -> PROXY.
# Прокси берётся из VLESS-подписки (политика PROXY). Своего [Proxy] тут нет.
# Add by URL: Config -> "+" -> Download from URL. Auto-updates via update-url.
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
{dns_block}
ipv6 = false
prefer-ipv6 = false
dns-direct-system = false
dns-fallback-system = false
dns-direct-fallback-proxy = true
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
udp-policy-not-supported-behaviour = REJECT
update-url = {update_url}

[Rule]"""

snap = json.load(open(SNAP))
services = snap.get("services", [])
if not services:
    sys.exit(f"{SNAP}: no services")

# Suffix-collapse: DOMAIN-SUFFIX,parent already matches every *.parent, so any
# domain whose dot-boundary parent is also listed is dead weight. opencck ships
# parent + dozens of subdomains -> ~90% of domain rules are redundant. We drop
# them (zero routing change) and dedup CIDRs across services. Same coverage,
# ~80% fewer rules -> lighter on Shadowrocket's per-connection matching.
_all_domains = set()
for svc in services:
    for d in svc.get("domains", []):
        d = d.strip().lower().rstrip(".")
        if d:
            _all_domains.add(d)


def _redundant(d):
    parts = d.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in _all_domains:
            return True
    return False


# build the shared rule body once
rule_lines = []
all_cidrs, seen, seen_dom = [], set(), set()
n_dom = n_v4 = n_v6 = 0
for svc in sorted(services, key=lambda s: (s.get("category", ""), s.get("slug", ""))):
    domains = sorted({d.strip().lower().rstrip(".") for d in svc.get("domains", []) if d.strip()})
    domains = [d for d in domains if not _redundant(d) and d not in seen_dom]
    v4 = [c.strip() for c in svc.get("cidr4", []) if c.strip() and c.strip() not in seen]
    v6 = [c.strip() for c in svc.get("cidr6", []) if c.strip() and c.strip() not in seen]
    if not (domains or v4 or v6):
        continue
    rule_lines.append("")
    rule_lines.append(f"# {svc.get('slug','')} ({svc.get('category','')})")
    for d in domains:
        rule_lines.append(f"DOMAIN-SUFFIX,{d},PROXY"); n_dom += 1; seen_dom.add(d)
    for c in v4:
        rule_lines.append(f"IP-CIDR,{c},PROXY,no-resolve"); n_v4 += 1
        seen.add(c); all_cidrs.append(c)
    for c in v6:
        rule_lines.append(f"IP-CIDR6,{c},PROXY,no-resolve"); n_v6 += 1
        seen.add(c); all_cidrs.append(c)

TAIL = [
    "", "# LAN",
    "IP-CIDR,192.168.0.0/16,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,172.16.0.0/12,DIRECT", "IP-CIDR,127.0.0.0/8,DIRECT",
    "", "FINAL,DIRECT", "", "[Host]", "localhost = 127.0.0.1", "",
]


def write(path, title, dns_block, update_url):
    body = [general(title, dns_block, update_url)] + rule_lines + TAIL
    open(path, "w").write("\n".join(body))


write(os.path.join(HERE, "split.conf"), "SPLIT (public, Cloudflare DNS)", DNS_PUBLIC,
      "https://raw.githubusercontent.com/baklaki52/iplist-mirror/main/sr/split.conf")
# private: update-url set after the secret gist exists; empty -> SR just won't auto-update
write(os.path.join(HERE, "split-private.conf"), "SPLIT (private, our DoH)", DNS_PRIVATE,
      os.environ.get("PRIVATE_UPDATE_URL", "https://baton.telescope.cv/sr/split-private.conf"))

# flat list for the RULE-SET variant
hdr = ["# blocked-services.list — flat RU-subtracted CIDR set from snapshot-ru-clean.json",
       f"# {len(all_cidrs)} CIDRs",
       "# Policy + no-resolve come from the RULE-SET reference in the .conf"]
flat = [f"IP-CIDR6,{c}" if ":" in c else f"IP-CIDR,{c}" for c in all_cidrs]
open(os.path.join(HERE, "blocked-services.list"), "w").write("\n".join(hdr + flat) + "\n")

print(f"split.conf (public, CF DNS) + split-private.conf (our DoH): "
      f"{n_dom} domains + {n_v4} v4 + {n_v6} v6")
print(f"blocked-services.list: {len(all_cidrs)} unique CIDRs")
