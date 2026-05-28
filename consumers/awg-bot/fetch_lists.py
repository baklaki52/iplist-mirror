#!/usr/bin/env python3
"""
fetch_lists.py — auto-update allowed_ips*.json from upstream mirror.

Runs hourly via cron. Reads `baklaki52/iplist-mirror` (our daily snapshot of
`rekryt/iplist`), applies the same curation the kvn-vpn Go project uses
(blacklist + category overrides + overlay additions), merges in admin-added
domains, and rewrites the three legacy JSON files bot.py/web.py already read:

  allowed_ips.json         — flat v4 CSV  (default split-tunnel list)
  allowed_ips_v6.json      — flat v6 list
  allowed_ips_youtube.json — YouTube-only subset

Plus one new file:

  allowed_ips_by_category.json — {"v4":{"ai":[...],"socials":[...]},"v6":{...}}
                                 used later for per-peer preset selection.

And bookkeeping:

  ip_lists_meta.json       — per-category sha256 + generated_at for diff detect
  admin_domains.json       — editable list of extra domains (starts as [])
  pending_alert.json       — written when diff detected; consumed by
                             alert_bot.py on next cron tick

Backward-compat: existing bot.py and web.py keep working unchanged — they
still read allowed_ips.json, allowed_ips_v6.json, allowed_ips_youtube.json.

Run:
  python3 fetch_lists.py            # full fetch + resolve + write
  python3 fetch_lists.py --no-resolve  # skip DNS resolution (for tests)
"""

import hashlib
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).parent
MIRROR = "https://raw.githubusercontent.com/baklaki52/iplist-mirror/main/snapshot-ru-clean.json"
MIRROR_SHA = "https://raw.githubusercontent.com/baklaki52/iplist-mirror/main/snapshot-ru-clean.sha256"

# ──────────────────────────────────────────────────────────────────────────
# Sync with kvn-vpn (as of 2026-04-18). Keep these aligned when kvn-vpn
# overlay/files/*.yaml changes — see UPLIFT.md.
# ──────────────────────────────────────────────────────────────────────────

# From iplist/types.go ForbiddenSlugs — drop entirely.
FORBIDDEN_SLUGS = {
    "navalny.com",        # extremist in RU
    "gordonua.com",       # UA project
    "korrespondent.net",
    "unian.net",
    "krymr.com",
    "currenttime.tv",     # Radio Svoboda / VOA
    "svoboda.org",
    "radiosvoboda.org",
    "golosameriki.com",
}

# Hard category filter (iplist/types.go ForbiddenCategories).
FORBIDDEN_CATEGORIES = {"casino"}

# Slug → new category (kvn-vpn 01-ai-category.yaml + 02-work-category.yaml).
CATEGORY_OVERRIDES = {
    "chatgpt.com":         "ai",
    "claude.ai":           "ai",
    "copilot":             "ai",
    "aistudio.google.com": "ai",
    "perplexity.ai":       "ai",
    "kilo.ai":             "ai",
    "grok.com":            "ai",
    "miro.com":            "work",
    "notion.so":           "work",
    "stripe":              "work",  # was `shop`; work preset needs it
}

# Overlay services — not in upstream. Each is added as a virtual service
# with manual CIDRs + resolved domain IPs merged.
# (kvn-vpn overlay/files/search.yaml + shop.yaml)
OVERLAY_SERVICES = [
    {
        # Anthropic-owned /21 (160.79.104.0–160.79.111.255). Their public
        # ASN AS398093 announces only 142.202.46.0/24 — the bulk of
        # claude.ai/console.anthropic.com/api.anthropic.com lives at
        # 160.79.104.x outside any announced AS. Manual prefix until
        # Anthropic publishes proper BGP announcements.
        "slug": "claude.ai",
        "name": "Claude (Anthropic)",
        "category": "ai",
        "domains": ["claude.ai", "console.anthropic.com", "api.anthropic.com"],
        "manual_cidr4": ["160.79.104.0/21"],
        "manual_cidr6": [],
    },
    {
        "slug": "startpage.com",
        "name": "StartPage",
        "category": "search",
        "domains": ["startpage.com", "www.startpage.com", "s.startpage.com"],
        "manual_cidr4": ["149.50.220.0/24", "67.63.59.0/24"],
        "manual_cidr6": [],
    },
    {
        "slug": "stripe",
        "name": "Stripe",
        "category": "work",  # matches override above
        "domains": [
            "stripe.com",
            "api.stripe.com",
            "checkout.stripe.com",
            "js.stripe.com",
            "m.stripe.com",
        ],
        "manual_cidr4": [],
        "manual_cidr6": [],
    },
]

# Categories included in default-mode allowed_ips.json. New `ai` + `work`
# added compared to pre-uplift baton (which had flat list of ~2000 CIDR).
DEFAULT_CATEGORIES = [
    "tools", "search", "news", "video", "youtube", "socials",
    "messengers", "music", "shop", "education", "art", "anime",
    "games", "jetbrains", "discord", "torrent",
    "ai", "work", "porn",
]

# Presets mirror kvn-vpn handlers/presets.go.
PRESETS = {
    "social":    ["socials", "messengers", "discord", "youtube", "video", "work", "jetbrains"],
    "social-ai": ["socials", "messengers", "discord", "youtube", "video", "work", "jetbrains", "ai"],
    "all":       list(DEFAULT_CATEGORIES),
}

# Anti-detect: Yandex (AS13238) prefixes — surgically subtracted from ALL
# categories. Problem: upstream iplist colocates Yandex CIDRs inside
# `socials` / `messengers` / `tools`, so any wide preset tunnels Yandex
# services. Once in the tunnel, Yandex-side geoip sees the VPN server IP
# and flags the user as VPN → native Yandex apps + any site embedding
# Yandex.Metrika (2gis, vkusvill) start refusing to work.
#
# Subtract these prefixes arithmetically via ipaddress.address_exclude()
# so the remaining CIDRs still cover the legitimate services in the
# category but nothing that would route Yandex through the tunnel.
# Telegram/WhatsApp/TikTok real v6 IPs are NOT in 2a02:6b8::/32
# (verified: Telegram in 2001:67c:4e8::, WhatsApp in 2a03:2880::,
# TikTok on Akamai CDN), so they remain tunneled unchanged.
YANDEX_V4_PREFIXES = [
    "5.45.192.0/18", "5.255.192.0/18",
    "37.9.64.0/18",  "37.140.128.0/18",
    "77.88.0.0/18",
    "87.250.224.0/19", "87.250.240.0/20",
    "93.158.128.0/18",
    "95.108.128.0/17",
    "141.8.128.0/17",
    "178.154.128.0/17",
    "185.32.184.0/22",
    "199.21.96.0/22", "199.36.240.0/22",
    "213.180.192.0/19",
]
YANDEX_V6_PREFIXES = [
    "2a02:6b8::/32",  # the whole AS13238 v6 block
]

# ──────────────────────────────────────────────────────────────────────────
# PRIORITY HEAD — top services pinned to the FRONT of AllowedIPs so they
# survive iOS NetworkExtension memory pressure / app-side connection timing.
# Order matters: these go first (v4), then their v6, then the rest.
# Explicit ASN blocks because ChatGPT/Gemini live on shared Cloudflare/Google
# ranges and cannot be isolated per-service from upstream iplist.
# ──────────────────────────────────────────────────────────────────────────
PRIORITY_CIDR_V4 = [
    # ── Telegram (AS62041) ──
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
    "91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20",
    "149.154.160.0/20", "149.154.164.0/22",
    # ── Google / YouTube / Gemini (AS15169) ──
    "8.8.4.0/24", "8.8.8.0/24", "34.0.0.0/9", "35.184.0.0/13",
    "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18",
    "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16",
    "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19",
    "216.239.32.0/19",
    # ── Meta / WhatsApp / Instagram (+ AWS edges for WA) ──
    "31.13.64.0/18", "57.144.0.0/14", "102.132.96.0/20", "157.240.0.0/16",
    "163.70.128.0/17", "179.60.0.0/16", "185.60.216.0/22",
    "3.33.128.0/17", "3.33.252.0/24", "15.197.0.0/16",
    # ── Cloudflare (ChatGPT, Claude edge, many CDN) ──
    "104.16.0.0/13", "104.24.0.0/14", "162.159.0.0/16", "172.64.0.0/13",
    "188.114.96.0/20",
    # ── Anthropic / Claude ──
    "160.79.104.0/21",
]
PRIORITY_CIDR_V6 = [
    # ── Telegram ──
    "2001:67c:4e8::/48", "2001:b28:f23c::/46", "2001:b28:f23f::/48",
    "2a0a:f280::/32",
    # ── Google / YouTube / Gemini ──
    "2607:f8b0::/32", "2800:3f0::/32", "2a00:1450::/32", "2404:6800::/32",
    "2001:4860::/32",
    # ── Meta / WhatsApp / Instagram ──
    "2a03:2880::/29",
    # ── Cloudflare (ChatGPT, Claude) ──
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29",
]

# ──────────────────────────────────────────────────────────────────────────
# IO helpers
# ──────────────────────────────────────────────────────────────────────────


def fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "awg-bot-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def atomic_write(path: Path, data: str) -> None:
    """Write via tmp + rename so concurrent readers never see a half-written file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data)
    tmp.replace(path)


def resolve_domain(domain: str, timeout: float = 3.0):
    """Return (v4_cidrs, v6_cidrs) — IPs as /32 and /128."""
    v4, v6 = set(), set()
    socket.setdefaulttimeout(timeout)
    try:
        for family, _, _, _, addr in socket.getaddrinfo(domain, None):
            ip = addr[0]
            if family == socket.AF_INET:
                v4.add(f"{ip}/32")
            elif family == socket.AF_INET6:
                # getaddrinfo may return v6 with scope (fe80::1%eth0); strip it
                v6.add(f"{ip.split('%', 1)[0]}/128")
    except (socket.gaierror, socket.timeout, OSError):
        pass
    finally:
        socket.setdefaulttimeout(None)
    return sorted(v4), sorted(v6)


def _hash_sorted(items) -> str:
    h = hashlib.sha256()
    for item in sorted(items):
        h.update(item.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def _subtract_excluded(cidr_strings, excluded_strings):
    """Arithmetically subtract excluded CIDRs from a list of CIDR strings.

    For each input CIDR we check overlap with each excluded CIDR and use
    ipaddress.Network.address_exclude() to chop out the overlap region
    (expands the network into the minimum set of prefixes that cover
    'self minus excluded'). If there is no overlap the CIDR passes through
    unchanged. Final result is re-collapsed via collapse_addresses().

    Example: net=77.0.0.0/8, exclude=77.88.0.0/18 → subnets covering
    77.0.0.0/8 without 77.88.0.0/18.

    Empty excluded list → just return sorted collapse of input (identity).
    """
    if not excluded_strings:
        # Still collapse to canonical form.
        try:
            return sorted(
                {str(n) for n in ipaddress.collapse_addresses(
                    [ipaddress.ip_network(c, strict=False) for c in cidr_strings]
                )},
                key=lambda s: ipaddress.ip_network(s),
            )
        except Exception:
            return sorted(cidr_strings)

    excluded_nets = []
    for s in excluded_strings:
        try:
            excluded_nets.append(ipaddress.ip_network(s, strict=False))
        except Exception:
            pass

    result_networks = []
    for c in cidr_strings:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except Exception:
            continue
        # Start with the single network; repeatedly chop each excluded
        # prefix out of every remaining piece.
        pieces = [net]
        for exc in excluded_nets:
            if exc.version != net.version:
                continue
            new_pieces = []
            for p in pieces:
                if not p.overlaps(exc):
                    new_pieces.append(p)
                    continue
                if p.subnet_of(exc):
                    # Whole piece is inside excluded → drop it.
                    continue
                if exc.subnet_of(p):
                    # Hole-punch inside the piece.
                    new_pieces.extend(p.address_exclude(exc))
                    continue
                # Partial overlap that isn't strictly subset either way
                # shouldn't happen with canonical prefixes, but be safe:
                new_pieces.append(p)
            pieces = new_pieces
        result_networks.extend(pieces)

    # Canonical minimum set.
    collapsed = ipaddress.collapse_addresses(result_networks)
    return sorted({str(n) for n in collapsed}, key=lambda s: ipaddress.ip_network(s))


# ──────────────────────────────────────────────────────────────────────────
# Pipeline
# ──────────────────────────────────────────────────────────────────────────


def fetch_upstream():
    """Download snapshot.json, verify sha256, return services list."""
    expected_sha = fetch(MIRROR_SHA).decode().strip().split()[0]
    body = fetch(MIRROR)
    actual_sha = hashlib.sha256(body).hexdigest()
    if actual_sha != expected_sha:
        raise SystemExit(f"snapshot sha256 mismatch: expected {expected_sha}, got {actual_sha}")
    data = json.loads(body)
    return data["services"]


def apply_filters(services):
    """Drop forbidden slugs/categories, apply category overrides."""
    out = []
    for s in services:
        if s["slug"] in FORBIDDEN_SLUGS:
            continue
        if s["category"] in FORBIDDEN_CATEGORIES:
            continue
        s2 = dict(s)
        if s["slug"] in CATEGORY_OVERRIDES:
            s2["category"] = CATEGORY_OVERRIDES[s["slug"]]
        out.append(s2)
    return out


def add_overlay(services, resolve: bool):
    """Append overlay services (StartPage, Stripe), resolving domains."""
    out = list(services)
    for ov in OVERLAY_SERVICES:
        cidr4 = list(ov["manual_cidr4"])
        cidr6 = list(ov["manual_cidr6"])
        if resolve:
            for d in ov["domains"]:
                r4, r6 = resolve_domain(d)
                cidr4 += r4
                cidr6 += r6
        out.append({
            "slug": ov["slug"],
            "name": ov["name"],
            "category": ov["category"],
            "cidr4": sorted(set(cidr4)),
            "cidr6": sorted(set(cidr6)),
            "domains": list(ov["domains"]),
            "dns": [],
        })
    return out


def resolve_admin_domains(resolve: bool):
    """Read admin_domains.json, resolve, return (v4,v6) cidrs."""
    p = BASE / "admin_domains.json"
    if not p.exists():
        return [], []
    try:
        domains = json.loads(p.read_text())
    except Exception:
        return [], []
    if not isinstance(domains, list):
        return [], []
    v4, v6 = set(), set()
    if resolve:
        for d in domains:
            r4, r6 = resolve_domain(d)
            v4.update(r4)
            v6.update(r6)
    return sorted(v4), sorted(v6)


def resolve_user_domains(resolve: bool):
    """Read user_domains.json (dict tg_id_str → [domains]), resolve each user's
    list, write user_domain_ips.json with the same shape keyed by tg_id_str
    but values = {v4: [...], v6: [...]}.

    Cache: identical domains resolved once per run even if multiple users
    added the same name."""
    p = BASE / "user_domains.json"
    if not p.exists():
        return
    try:
        user_map = json.loads(p.read_text())
    except Exception:
        return
    if not isinstance(user_map, dict):
        return

    cache_v4 = {}
    cache_v6 = {}
    out = {}
    for tg_id_str, domains in user_map.items():
        if not isinstance(domains, list):
            continue
        v4, v6 = set(), set()
        if resolve:
            for d in domains:
                if d in cache_v4:
                    v4.update(cache_v4[d])
                    v6.update(cache_v6[d])
                    continue
                r4, r6 = resolve_domain(d)
                cache_v4[d] = r4
                cache_v6[d] = r6
                v4.update(r4)
                v6.update(r6)
        out[tg_id_str] = {"v4": sorted(v4), "v6": sorted(v6)}

    atomic_write(BASE / "user_domain_ips.json", json.dumps(out, sort_keys=True))


# ──────────────────────────────────────────────────────────────────────────
# Static popularity ranking (RU usage). Lower number = more popular = earlier
# in AllowedIPs. Per-service slug overrides take priority; otherwise the
# service's category rank is used. Replace with dynamic dns-query stats later.
# ──────────────────────────────────────────────────────────────────────────
SERVICE_POPULARITY = {
    "telegram.org": 1, "telegram.me": 1, "t.me": 1,
    "youtube.com": 2, "youtu.be": 2, "googlevideo.com": 2, "ytimg.com": 2,
    "whatsapp.com": 3, "whatsapp.net": 3,
    "instagram.com": 4, "cdninstagram.com": 4,
    "chatgpt.com": 5, "openai.com": 5, "oaistatic.com": 5, "oaiusercontent.com": 5,
    "google.com": 6, "gstatic.com": 6, "googleapis.com": 6, "ggpht.com": 6,
    "discord.com": 7, "discord.gg": 7, "discordapp.com": 7, "discordapp.net": 7,
    "gemini.google.com": 8, "aistudio.google.com": 8, "bard.google.com": 8,
    "claude.ai": 9, "anthropic.com": 9, "claude": 9, "anthropic": 9,
    "twitter.com": 10, "x.com": 10, "twimg.com": 10, "t.co": 10,
    "facebook.com": 11, "fbcdn.net": 11, "fb.com": 11,
    "spotify.com": 12, "scdn.co": 12,
    "soundcloud.com": 13, "sndcdn.com": 13,
    "twitch.tv": 14, "ttvnw.net": 14,
    "tiktok.com": 15, "tiktokcdn.com": 15,
    "signal.org": 16,
    "github.com": 17, "githubusercontent.com": 17, "githubassets.com": 17,
    "reddit.com": 18, "redd.it": 18, "redditstatic.com": 18,
    "netflix.com": 19, "nflxvideo.net": 19,
    "linkedin.com": 20,
}
CATEGORY_POPULARITY = {
    "messengers": 100, "youtube": 105, "ai": 110, "discord": 115,
    "socials": 120, "video": 140, "music": 150, "games": 170,
    "search": 180, "news": 190, "work": 200, "shop": 210,
    "tools": 220, "education": 230, "jetbrains": 240, "art": 250,
    "anime": 260, "torrent": 270, "porn": 280,
}


def _service_rank(s):
    """Lower = more popular = earlier in the list."""
    slug = (s.get("slug") or "").lower()
    if slug in SERVICE_POPULARITY:
        return SERVICE_POPULARITY[slug]
    return CATEGORY_POPULARITY.get(s.get("category", ""), 500)


def build_ordered(services, admin_v4, admin_v6):
    """Single ranked array: services by popularity, each service's v4 then v6
    adjacent. Deduped (first-seen wins), Yandex subtracted per-service."""
    ranked = sorted(services, key=lambda s: (_service_rank(s), s.get("slug", "")))
    seen = set()
    ordered = []
    for s in ranked:
        v4 = _subtract_excluded(list(s.get("cidr4", [])), YANDEX_V4_PREFIXES)
        v6 = _subtract_excluded(list(s.get("cidr6", [])), YANDEX_V6_PREFIXES)
        for cidr in v4 + v6:          # v4 first, then v6 — adjacent per service
            c = cidr.strip()
            if c and c not in seen:
                seen.add(c)
                ordered.append(c)
    # admin domains last (operator extras, not popularity-ranked)
    for cidr in list(admin_v4) + list(admin_v6):
        c = (cidr or "").strip()
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def build_outputs(services, admin_v4, admin_v6):
    by_cat_v4 = {}
    by_cat_v6 = {}
    services_by_cat = {}
    for s in services:
        cat = s["category"]
        by_cat_v4.setdefault(cat, set()).update(s.get("cidr4", []))
        by_cat_v6.setdefault(cat, set()).update(s.get("cidr6", []))
        services_by_cat.setdefault(cat, []).append({
            "slug": s.get("slug", ""),
            "name": s.get("name") or s.get("slug", ""),
        })

    all_v4 = set()
    all_v6 = set()
    for cat in DEFAULT_CATEGORIES:
        all_v4.update(by_cat_v4.get(cat, set()))
        all_v6.update(by_cat_v6.get(cat, set()))

    # Admin domains always included in the flat list (affects default split).
    all_v4.update(admin_v4)
    all_v6.update(admin_v6)

    # Anti-detect: carve Yandex prefixes out of every bucket (flat + per-cat)
    # via arithmetic subset subtraction. This is the surgical variant of
    # "remove the whole Yandex /62": we keep the non-Yandex parts of any
    # CIDR that partially overlaps with AS13238, so legitimate services in
    # `socials`/`messengers` stay reachable through the tunnel.
    flat_v4 = _subtract_excluded(list(all_v4), YANDEX_V4_PREFIXES)
    flat_v6 = _subtract_excluded(list(all_v6), YANDEX_V6_PREFIXES)
    yt_v4 = _subtract_excluded(list(by_cat_v4.get("youtube", set())), YANDEX_V4_PREFIXES)

    by_cat_v4_out = {
        k: _subtract_excluded(list(v), YANDEX_V4_PREFIXES)
        for k, v in by_cat_v4.items()
    }
    by_cat_v6_out = {
        k: _subtract_excluded(list(v), YANDEX_V6_PREFIXES)
        for k, v in by_cat_v6.items()
    }
    # admin_domains aren't subject to the exclusion — they're added
    # explicitly by operator, no reason to filter them.
    by_cat_v4_out["_admin_domains"] = admin_v4
    by_cat_v6_out["_admin_domains"] = admin_v6

    # Deterministic service lists — sort by slug so bot UI is stable.
    services_by_cat = {
        cat: sorted(entries, key=lambda x: x["slug"])
        for cat, entries in services_by_cat.items()
    }

    # PRIORITY HEAD — explicit ordered list, deduped, Yandex-filtered.
    # bot.py prepends this so critical services sit at the front of AllowedIPs.
    _pri_v4 = _subtract_excluded(list(PRIORITY_CIDR_V4), YANDEX_V4_PREFIXES)
    _pri_v6 = _subtract_excluded(list(PRIORITY_CIDR_V6), YANDEX_V6_PREFIXES)
    # Preserve declared order (subtract_excluded may reorder) — re-sort to
    # match the PRIORITY_CIDR_* declaration order, keeping any split fragments
    # adjacent to their parent.
    def _in_order(declared, produced):
        produced_set = set(produced)
        out, seen = [], set()
        for c in declared:
            # exact match first
            if c in produced_set and c not in seen:
                out.append(c); seen.add(c)
        # any fragments from subtraction that aren't exact declared entries
        for c in produced:
            if c not in seen:
                out.append(c); seen.add(c)
        return out
    priority_v4 = _in_order(PRIORITY_CIDR_V4, _pri_v4)
    priority_v6 = _in_order(PRIORITY_CIDR_V6, _pri_v6)

    ordered = build_ordered(services, admin_v4, admin_v6)

    return {
        "allowed_ips.json": flat_v4,
        "allowed_ips_v6.json": flat_v6,
        "allowed_ips_ordered.json": ordered,
        "allowed_ips_priority.json": {"v4": priority_v4, "v6": priority_v6},
        "allowed_ips_youtube.json": yt_v4,
        "allowed_ips_by_category.json": {
            "v4": by_cat_v4_out,
            "v6": by_cat_v6_out,
        },
        "services_by_category.json": services_by_cat,
    }


def compute_hashes(by_category):
    h = {}
    for cat, items in by_category["v4"].items():
        h[f"v4:{cat}"] = _hash_sorted(items)
    for cat, items in by_category["v6"].items():
        h[f"v6:{cat}"] = _hash_sorted(items)
    return h


def diff_hashes(old, new):
    changed = []
    for key in set(old.keys()) | set(new.keys()):
        if old.get(key) != new.get(key):
            family, cat = key.split(":", 1)
            changed.append((family, cat))
    return changed


# Alert throttling policy (caught the 'не дёргай меня каждый час' feedback).
#
#   - Hourly fetch keeps running, diff is computed every tick.
#   - Alert fires ONLY if one of these holds:
#       a) at least ALERT_CRITICAL_CATS categories changed in a single tick
#          (a broad sweep → probably worth immediate attention);
#       b) 48 hours passed since the last alert AND anything is pending.
#   - Between alerts, changed categories accumulate in ip_lists_meta.json
#     so when the alert finally fires it lists the full set, not just
#     whatever happened on the last tick.
ALERT_THROTTLE_SECONDS = 48 * 3600
ALERT_CRITICAL_CATS = 5


def main():
    resolve = "--no-resolve" not in sys.argv

    services_raw = fetch_upstream()
    services = apply_filters(services_raw)
    services = add_overlay(services, resolve=resolve)
    admin_v4, admin_v6 = resolve_admin_domains(resolve=resolve)
    # Per-user domains are now resolved inline by bot.py (rich-format
    # user_domains.json with {domain, ips_v4, ips_v6, resolved_at} entries).
    # generate_client_config reads them via ud.collect_ips() — no separate
    # user_domain_ips.json file needed. Migration: 2026-04-25.

    outputs = build_outputs(services, admin_v4, admin_v6)

    atomic_write(BASE / "allowed_ips.json",
                 json.dumps(outputs["allowed_ips.json"]))
    atomic_write(BASE / "allowed_ips_ordered.json",
                 json.dumps(outputs["allowed_ips_ordered.json"]))
    atomic_write(BASE / "allowed_ips_priority.json",
                 json.dumps(outputs["allowed_ips_priority.json"]))
    atomic_write(BASE / "allowed_ips_v6.json",
                 json.dumps(outputs["allowed_ips_v6.json"]))
    atomic_write(BASE / "allowed_ips_youtube.json",
                 json.dumps(outputs["allowed_ips_youtube.json"]))
    atomic_write(BASE / "allowed_ips_by_category.json",
                 json.dumps(outputs["allowed_ips_by_category.json"], sort_keys=True))
    atomic_write(BASE / "services_by_category.json",
                 json.dumps(outputs["services_by_category.json"],
                            sort_keys=True, ensure_ascii=False))

    new_hashes = compute_hashes(outputs["allowed_ips_by_category.json"])
    meta_path = BASE / "ip_lists_meta.json"
    old_meta = {}
    if meta_path.exists():
        try:
            old_meta = json.loads(meta_path.read_text()) or {}
        except Exception:
            pass
    old_hashes = old_meta.get("hashes", {})
    last_alerted_at = old_meta.get("last_alerted_at", 0)
    accumulated = set(old_meta.get("pending_changed_cats", []))

    changes = diff_hashes(old_hashes, new_hashes)
    changed_cats_this_tick = sorted({cat for _, cat in changes})
    accumulated.update(changed_cats_this_tick)

    now = int(time.time())

    alert_sent = False
    alert_reason = "no-changes"
    if old_hashes and accumulated:
        time_since = now - last_alerted_at if last_alerted_at else None
        critical_now = len(changed_cats_this_tick) >= ALERT_CRITICAL_CATS
        throttle_expired = last_alerted_at == 0 or time_since >= ALERT_THROTTLE_SECONDS
        if critical_now:
            alert_reason = f"critical ({len(changed_cats_this_tick)} cats in one tick)"
        elif throttle_expired:
            alert_reason = (f"throttle-expired ({len(accumulated)} cats accumulated"
                            f"{', first run' if last_alerted_at == 0 else ''})")
        else:
            remaining = ALERT_THROTTLE_SECONDS - time_since
            alert_reason = f"throttled ({remaining//3600}h left, {len(accumulated)} cats pending)"

        if critical_now or throttle_expired:
            alert = {
                "alert_id": f"diff-{now}",
                "ts": now,
                "type": "catalog-diff",
                "changed_categories": sorted(accumulated),
                "changed_this_tick": changed_cats_this_tick,
                "critical": critical_now,
                "services_count": len(services),
            }
            atomic_write(BASE / "pending_alert.json", json.dumps(alert))
            last_alerted_at = now
            accumulated.clear()
            alert_sent = True

    atomic_write(meta_path, json.dumps({
        "generated_at": now,
        "generated_at_human": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "source": MIRROR,
        "services_count": len(services),
        "admin_domains_count_v4": len(admin_v4),
        "admin_domains_count_v6": len(admin_v6),
        "hashes": new_hashes,
        "last_alerted_at": last_alerted_at,
        "pending_changed_cats": sorted(accumulated),
    }, sort_keys=True))

    if not old_hashes:
        print(f"OK: services={len(services)} first run, no alert")
    elif alert_sent:
        print(f"OK: services={len(services)} ALERT sent — {alert_reason}")
    else:
        print(f"OK: services={len(services)} {alert_reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
