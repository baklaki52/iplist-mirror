#!/usr/bin/env python3
"""geoblock_overlay.py — inject a curated slice of RussiaFancyLists `geoblock`
domains into snapshot.json and snapshot-ru-clean.json as one synthetic service.

Why:
  RussiaFancyLists (MIT, refreshed every ~3h) publishes `geoblock/domains/full-sld.lst`
  — services that geo-restrict Russian IPs (hosting/dev/banks/AI/gaming/etc). The
  upstream opencck catalog (fetch.sh) does NOT cover them, so they never reach the
  Vezdehod routing profile. This overlay pulls the list, keeps only domains matching
  our curated category patterns (avoids dragging in casino/piracy noise), and merges
  them as a single service record `vezdehod-geoblock` so the downstream kvn publisher
  picks them up automatically on its daily cron.

Design:
  - Domain-only (geoblock has no CIDR) → filter_ru.py (CIDR subtraction) leaves it
    untouched; safe to run either before or after filter_ru. We patch BOTH
    snapshot.json and snapshot-ru-clean.json so the diff-gate and the kvn publisher
    (which fetches snapshot-ru-clean.json) both see it.
  - Curated slice only (category patterns) → keeps the profile bounded (~50 domains,
    not 506) and matches the operator's manual STATIC_PROXY curation, but auto-fresh.
  - Idempotent: re-running replaces the existing vezdehod-geoblock service.
  - Fail-soft: geoblock fetch failure logs a warning and leaves snapshots untouched
    (better stale-but-valid than broken). Stdlib only.

Env:
  GEOBLOCK_URL   override source (default RussiaFancyLists geoblock full-sld.lst)
"""
import json
import os
import sys
import subprocess
import urllib.request

GEOBLOCK_URL = os.environ.get(
    "GEOBLOCK_URL",
    "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/geoblock/domains/full-sld.lst",
)
SLUG = "vezdehod-geoblock"

# Curated category patterns — keep only domains we actually want in the tunnel.
# Substring match against the SLD; broaden here to catch new brands automatically.
PATTERNS = [
    # hosting / cloud (panels, not shared CDN)
    "digitalocean", "hetzner", "linode", "vultr", "ovh", "heroku", "vercel", "netlify",
    "fly.io", "render", "railway", "scaleway", "oracle", "hostinger", "contabo", "upcloud",
    "kamatera", "dreamhost", "namecheap",
    # dev / software
    "github", "gitlab", "docker", "npm", "pypi", "jetbrains", "hashicorp", "terraform",
    "kubernetes", "atlassian", "bitbucket", "adobe", "autodesk", "nvidia", "amd", "intel",
    "figma", "notion", "postman", "gradle", "unity", "jfrog", "sentry", "redhat", "ubuntu",
    "debian", "gitea",
    # banks / fintech
    "paypal", "stripe", "wise", "transferwise", "revolut", "payoneer", "n26", "monzo",
    "mercury", "sofi", "binance", "coinbase", "kraken", "tradingview", "interactivebrokers",
    "plaid", "robinhood",
    # AI / essential
    "openai", "anthropic", "huggingface", "replicate", "cursor", "perplexity", "midjourney",
    "stability", "deepmind", "cohere", "tailscale", "runwayml", "elevenlabs",
    # productivity tools
    "slack", "zoom", "dropbox", "trello", "asana", "linear", "miro", "canva", "grammarly",
    "1password", "bitwarden", "proton", "loom", "calendly",
    # gaming
    "steam", "epicgames", "gog.com", "itch.io", "unrealengine", "playstation", "xbox",
    "nintendo", "ea.com", "ubisoft",
    # speed test
    "speedtest", "ookla",
]

# Broad shared-CDN roots we must NOT tunnel (amplifies third-party traffic).
CDN_DENY = {"amazonaws.com", "akamai.net", "akamaiedge.net", "akamaized.net", "fastly.net",
            "cloudflare.net", "azureedge.net"}


def fetch_geoblock():
    req = urllib.request.Request(GEOBLOCK_URL, headers={"User-Agent": "iplist-mirror-geoblock/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        text = r.read().decode("utf-8", "replace")
    doms = []
    for line in text.splitlines():
        d = line.strip().lower()
        if not d or d.startswith("#"):
            continue
        doms.append(d)
    return doms


def curate(domains):
    keep = []
    for d in domains:
        if d in CDN_DENY:
            continue
        if any(p in d for p in PATTERNS):
            keep.append(d)
    return sorted(set(keep))


def patch_snapshot(path, curated):
    if not os.path.isfile(path):
        print(f"  skip {path} (missing)", file=sys.stderr)
        return False
    snap = json.load(open(path))
    services = [s for s in snap.get("services", []) if s.get("slug") != SLUG]
    services.append({
        "slug": SLUG,
        "name": "Vezdehod geoblock overlay",
        "category": "geoblock",
        "cidr4": [],
        "cidr6": [],
        "domains": curated,
        "dns": [],
    })
    snap["services"] = sorted(services, key=lambda s: s["slug"])
    tmp = path + ".tmp"
    json.dump(snap, open(tmp, "w"), ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)
    # refresh sha256 sidecar if present
    sha_path = path.rsplit(".json", 1)[0] + ".sha256"
    if os.path.isfile(sha_path):
        digest = subprocess.run(["sha256sum", path], capture_output=True, text=True).stdout.split()[0]
        open(sha_path, "w").write(digest + "\n")
    return True


def main():
    try:
        raw = fetch_geoblock()
    except Exception as e:
        print(f"::warning::geoblock fetch failed ({e}) — snapshots left untouched", file=sys.stderr)
        return 0
    curated = curate(raw)
    if len(curated) < 10:
        print(f"::warning::geoblock curated slice too small ({len(curated)}) — skipping overlay", file=sys.stderr)
        return 0
    print(f"geoblock: {len(raw)} raw → {len(curated)} curated (service {SLUG})")
    for path in ("snapshot.json", "snapshot-ru-clean.json"):
        if patch_snapshot(path, curated):
            print(f"  patched {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
