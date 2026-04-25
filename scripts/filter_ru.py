#!/usr/bin/env python3
"""filter_ru.py — produce snapshot-ru-clean.json by subtracting Russian
country IP allocations from each service's cidr4/cidr6.

Input:   snapshot.json  (built by fetch.sh)
Outputs: snapshot-ru-clean.json   — same schema + extra `ru_filter` block
         snapshot-ru-clean.sha256 — hex digest of the clean snapshot
         ru_filter_report.json    — per-category / per-service breakdown

Why:
  Upstream catalog (rekryt/iplist via iplist.opencck.org) bundles a number
  of Russian ISP CIDRs into service categories where they don't belong —
  most notably ~40 RU prefixes inside `youtube` (Google removed RU GGC
  caches in 2022), but also Yandex Cloud blocks under `art`, RU CDN
  fragments under `anime`/`video`, etc. Routing those through a
  foreign-exit VPN is wasteful at best and broken at worst.

Sources (union — both applied):
  1. ipverse/rir-ip — RIPE-aggregated RU country allocations (broad).
     Catches everything RIPE-registered to RU, but misses RU services
     that front their domains on foreign IPs (Cloudflare/Akamai edge).
  2. russia.iplist.opencck.org — 77 curated RU service slugs
     (sber, vk, yandex, gosuslugi, ozon, …) with hourly DNS re-resolve.
     Catches RU-service IPs that live on foreign ASNs.

Strategy:
  Pure CIDR set subtraction (allowed - RU). For each {cidr4, cidr6} list
  in every service, drop any prefix fully inside a RU block, and split
  any prefix that strictly contains a RU block (using
  ipaddress.IPv4Network.address_exclude). Two CIDR networks are always
  either disjoint, equal, or one fully contains the other — there is no
  "partial overlap" to worry about.

Failure mode:
  Source #1 fetch failure aborts (it's authoritative for country-level RU).
  Source #2 fetch failure logs a warning and proceeds with #1 only —
  better partial coverage than no output. Either way, on hard failure the
  prior snapshot-ru-clean.json is left untouched.

Stdlib only — no pip dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

RU_V4_URL = (
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/"
    "country/ru/ipv4-aggregated.txt"
)
RU_V6_URL = (
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/"
    "country/ru/ipv6-aggregated.txt"
)
SOURCE_REPO = "ipverse/rir-ip"

# Secondary precise whitelist: 77 RU services (sber, gosuslugi, ozon, vk,
# yandex, etc.) — same maintainer as iplist.opencck.org, dedicated subdomain.
# Catches RU-service CIDRs hosted on foreign IPs (Cloudflare-fronted .ru
# domains, Akamai RU-edge), which ipverse/rir-ip misses because they're not
# RIPE-allocated to RU. Used together with rir-ip for full coverage.
RU_OPENCCK_V4_URL = (
    "https://russia.iplist.opencck.org/?format=text&data=cidr4&group=russia"
)
RU_OPENCCK_V6_URL = (
    "https://russia.iplist.opencck.org/?format=text&data=cidr6&group=russia"
)
RU_OPENCCK_REPO = "russia.iplist.opencck.org"
USER_AGENT = "iplist-mirror-bot/1.0 (+https://github.com/baklaki52/iplist-mirror)"
HTTP_TIMEOUT = 60
HTTP_RETRIES = 3
HTTP_BACKOFF = 5


def http_get(url: str) -> str:
    last_err: Exception | None = None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
            print(
                f"  retry {url} attempt={attempt} err={exc}",
                file=sys.stderr,
            )
            time.sleep(HTTP_BACKOFF)
    raise RuntimeError(f"GET {url} failed after {HTTP_RETRIES} attempts: {last_err}")


def parse_cidr_list(text: str, family: type) -> list:
    """Parse ipverse/rir-ip aggregated.txt format. Lines starting with '#'
    or empty lines are skipped."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if isinstance(net, family):
            out.append(net)
    return out


def _restrict_to_ipverse(opencck: list, ipverse: list) -> list:
    """Keep only opencck CIDRs that are fully contained within some
    ipverse RIPE-RU block. Opencck publishes A-records of RU services
    regardless of hosting AS, which includes Cloudflare/Google/AWS-fronted
    edges. Subtracting those wholesale destroys aggregation of foreign CDN
    blocks in unrelated categories. RIPE country allocation is the
    authoritative answer to "is this prefix Russian-operated", so we
    require opencck CIDRs to fall fully inside a RIPE-RU block.

    O(n*m) worst-case with a /8 (v4) or /16 (v6) bucket index, fine for
    ~1k opencck × ~10k ipverse.
    """
    if not opencck or not ipverse:
        return []
    sample = ipverse[0]
    if isinstance(sample, ipaddress.IPv4Network):
        shift = 24
    else:
        shift = 112
    buckets: dict[int, list] = defaultdict(list)
    for net in ipverse:
        start = int(net.network_address) >> shift
        end = int(net.broadcast_address) >> shift
        for k in range(start, end + 1):
            buckets[k].append(net)

    kept = []
    for cand in opencck:
        key = int(cand.network_address) >> shift
        if any(cand.subnet_of(rb) for rb in buckets.get(key, [])):
            kept.append(cand)
    return kept


def subtract_ru(allowed: list, ru: list) -> tuple[list, list]:
    """Return (filtered_allowed, removed) where each prefix in `ru` is
    excised from `allowed`. `allowed` order is preserved among
    non-overlapping prefixes; rewritten ones are appended in dependency
    order. Both inputs must be the same address family.

    Removed list captures *original* allowed prefixes that were touched
    (fully removed or split), for auditing.
    """
    if not allowed:
        return [], []
    # Index ru by /8 (v4) or /16 (v6) bucket so we don't scan all RU per
    # allowed prefix. Allowed prefixes can span multiple buckets; we use
    # network_address >> shift … broadcast_address >> shift as a range.
    sample = allowed[0]
    if isinstance(sample, ipaddress.IPv4Network):
        shift = 24
    else:
        shift = 112
    buckets: dict[int, list] = defaultdict(list)
    for net in ru:
        key = int(net.network_address) >> shift
        buckets[key].append(net)

    removed: list = []
    result: list = []

    for orig in allowed:
        # Collect RU prefixes overlapping this allowed prefix.
        start = int(orig.network_address) >> shift
        end = int(orig.broadcast_address) >> shift
        overlapping_ru: list = []
        seen_ids: set[int] = set()
        for k in range(start, end + 1):
            for r in buckets.get(k, []):
                rid = id(r)
                if rid in seen_ids:
                    continue
                if orig.overlaps(r):
                    seen_ids.add(rid)
                    overlapping_ru.append(r)
        if not overlapping_ru:
            result.append(orig)
            continue

        removed.append(orig)
        # Apply subtractions: maintain a working set of pieces, peel off
        # each RU block. Pieces that contain the block get split via
        # address_exclude; pieces fully inside the block get dropped;
        # pieces fully outside stay.
        pieces = [orig]
        for ru_net in overlapping_ru:
            new_pieces = []
            for piece in pieces:
                if piece == ru_net:
                    continue
                if piece.subnet_of(ru_net):
                    continue
                if ru_net.subnet_of(piece):
                    new_pieces.extend(piece.address_exclude(ru_net))
                else:
                    # Disjoint by construction (CIDR blocks can't partial-overlap).
                    new_pieces.append(piece)
            pieces = new_pieces
            if not pieces:
                break
        # Collapse pieces back to canonical aggregated form.
        if pieces:
            result.extend(ipaddress.collapse_addresses(pieces))

    return result, removed


def filter_snapshot(
    snap: dict, ru_v4: list, ru_v6: list, sources_meta: list
) -> tuple[dict, dict]:
    """Return (filtered_snap, report). filtered_snap is a deep-copy with
    cidr4/cidr6 rewritten. Report breaks down removals by category +
    service.

    sources_meta is a list of {repo, v4_url, v6_url, v4_count, v6_count, status}
    describing each RU source contributing to the union. Written into the
    snapshot's `ru_filter` block and the standalone report.
    """
    services = snap.get("services", [])
    new_services = []

    cat_stats: dict[str, dict] = defaultdict(
        lambda: {
            "v4_removed_prefix_count": 0,
            "v6_removed_prefix_count": 0,
            "v4_addresses_removed": 0,
            "v6_addresses_removed": 0,
            "services_touched": 0,
        }
    )
    per_service: list = []

    for svc in services:
        cidr4_in = [ipaddress.ip_network(c, strict=False) for c in svc.get("cidr4", [])]
        cidr6_in = [ipaddress.ip_network(c, strict=False) for c in svc.get("cidr6", [])]
        cidr4_out, removed_v4 = subtract_ru(cidr4_in, ru_v4)
        cidr6_out, removed_v6 = subtract_ru(cidr6_in, ru_v6)

        new_svc = dict(svc)
        new_svc["cidr4"] = sorted({str(c) for c in cidr4_out}, key=_sort_key_v4)
        new_svc["cidr6"] = sorted({str(c) for c in cidr6_out}, key=_sort_key_v6)
        new_services.append(new_svc)

        if removed_v4 or removed_v6:
            addrs_v4 = sum(r.num_addresses for r in removed_v4)
            addrs_v6 = sum(r.num_addresses for r in removed_v6)
            cat = svc.get("category", "_unknown")
            cs = cat_stats[cat]
            cs["v4_removed_prefix_count"] += len(removed_v4)
            cs["v6_removed_prefix_count"] += len(removed_v6)
            cs["v4_addresses_removed"] += addrs_v4
            cs["v6_addresses_removed"] += addrs_v6
            cs["services_touched"] += 1
            per_service.append(
                {
                    "slug": svc.get("slug"),
                    "category": cat,
                    "removed_v4": [str(r) for r in removed_v4],
                    "removed_v6": [str(r) for r in removed_v6],
                }
            )

    new_snap = dict(snap)
    new_snap["services"] = new_services
    new_snap["ru_filter"] = {
        "applied": True,
        "sources": sources_meta,
        "ru_v4_prefix_count": len(ru_v4),
        "ru_v6_prefix_count": len(ru_v6),
        "applied_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    report = {
        "schema_version": 1,
        "applied_at": new_snap["ru_filter"]["applied_at"],
        "sources": sources_meta,
        "ru_v4_prefix_count": len(ru_v4),
        "ru_v6_prefix_count": len(ru_v6),
        "totals": {
            "services_touched": sum(c["services_touched"] for c in cat_stats.values()),
            "v4_removed_prefix_count": sum(
                c["v4_removed_prefix_count"] for c in cat_stats.values()
            ),
            "v6_removed_prefix_count": sum(
                c["v6_removed_prefix_count"] for c in cat_stats.values()
            ),
            "v4_addresses_removed": sum(
                c["v4_addresses_removed"] for c in cat_stats.values()
            ),
            "v6_addresses_removed": sum(
                c["v6_addresses_removed"] for c in cat_stats.values()
            ),
        },
        "by_category": dict(cat_stats),
        "per_service": per_service,
    }
    return new_snap, report


def _sort_key_v4(s: str):
    n = ipaddress.ip_network(s, strict=False)
    return (int(n.network_address), n.prefixlen)


def _sort_key_v6(s: str):
    n = ipaddress.ip_network(s, strict=False)
    return (int(n.network_address), n.prefixlen)


def write_atomic(path: Path, content: bytes | str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    if isinstance(content, str):
        tmp.write_text(content)
    else:
        tmp.write_bytes(content)
    tmp.replace(path)


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", default="snapshot.json")
    p.add_argument("--output", default="snapshot-ru-clean.json")
    p.add_argument("--checksum", default="snapshot-ru-clean.sha256")
    p.add_argument("--report", default="ru_filter_report.json")
    p.add_argument(
        "--allow-fetch-failure",
        action="store_true",
        default=True,
        help="If RU lists can't be fetched, exit 0 leaving prior outputs in place.",
    )
    args = p.parse_args(argv)

    in_path = Path(args.input)
    out_path = Path(args.output)
    sum_path = Path(args.checksum)
    rep_path = Path(args.report)

    if not in_path.exists():
        print(f"FAIL: input {in_path} not found", file=sys.stderr)
        return 1

    print(f"filter_ru: input={in_path}")
    snap = json.loads(in_path.read_text())

    sources_meta: list = []

    # Source 1: ipverse/rir-ip — authoritative RIPE country block (broad).
    print(f"filter_ru: [1/2] fetching ipverse/rir-ip RU lists")
    try:
        ru_v4_text = http_get(RU_V4_URL)
        ru_v6_text = http_get(RU_V6_URL)
    except RuntimeError as exc:
        msg = f"WARN: RU fetch failed: {exc}"
        print(msg, file=sys.stderr)
        if args.allow_fetch_failure:
            print(
                "filter_ru: leaving previous outputs untouched (fetch failure tolerated)",
                file=sys.stderr,
            )
            return 0
        return 1

    ru_v4_ipverse = parse_cidr_list(ru_v4_text, ipaddress.IPv4Network)
    ru_v6_ipverse = parse_cidr_list(ru_v6_text, ipaddress.IPv6Network)
    print(
        f"filter_ru: [1/2] ipverse v4={len(ru_v4_ipverse)} v6={len(ru_v6_ipverse)}"
    )

    if not ru_v4_ipverse or not ru_v6_ipverse:
        print(
            "WARN: empty ipverse RU list — refusing to write potentially-broken output",
            file=sys.stderr,
        )
        return 0 if args.allow_fetch_failure else 1

    sources_meta.append(
        {
            "repo": SOURCE_REPO,
            "v4_url": RU_V4_URL,
            "v6_url": RU_V6_URL,
            "v4_prefix_count": len(ru_v4_ipverse),
            "v6_prefix_count": len(ru_v6_ipverse),
            "status": "ok",
        }
    )

    # Source 2: russia.iplist.opencck.org — 77 curated RU services (graceful).
    #
    # IMPORTANT: opencck publishes A-records of RU services regardless of
    # which AS hosts them. This includes Cloudflare-fronted .ru domains
    # (104.x.x.x), AWS-edge (52.x), and even the entire Google /16 blocks
    # (142.250.0.0/16, 142.251.0.0/16) when a RU site embeds Google services.
    #
    # Subtracting these wholesale destroys aggregation of foreign CDN blocks
    # in other categories (e.g. youtube): broad YT prefixes get split into
    # hundreds of tiny holes around Cloudflare/Google IPs that some RU site
    # happens to use. WireGuard clients then have to match against thousands
    # of tiny prefixes — observed real-world impact: YouTube playback delay.
    #
    # Fix: restrict opencck CIDRs to those FULLY WITHIN RIPE-allocated RU
    # blocks (source 1). This keeps the value of opencck — narrower RU
    # ranges that ipverse aggregation might miss (Yandex Cloud /16 inside
    # AS13238, MTS /16, Azure-RU tenant blocks) — while filtering out
    # global CDN prefixes that happen to host RU-fronted domains.
    print(f"filter_ru: [2/2] fetching {RU_OPENCCK_REPO}")
    ru_v4_opencck_raw: list = []
    ru_v6_opencck_raw: list = []
    opencck_status = "ok"
    try:
        ru_v4_opencck_text = http_get(RU_OPENCCK_V4_URL)
        ru_v6_opencck_text = http_get(RU_OPENCCK_V6_URL)
        ru_v4_opencck_raw = parse_cidr_list(ru_v4_opencck_text, ipaddress.IPv4Network)
        ru_v6_opencck_raw = parse_cidr_list(ru_v6_opencck_text, ipaddress.IPv6Network)
        print(
            f"filter_ru: [2/2] opencck raw v4={len(ru_v4_opencck_raw)} v6={len(ru_v6_opencck_raw)}"
        )
    except RuntimeError as exc:
        opencck_status = f"fetch_failed: {exc}"
        print(
            f"WARN: opencck RU fetch failed — proceeding with ipverse only: {exc}",
            file=sys.stderr,
        )

    # Restrict opencck CIDRs to those fully inside RIPE-RU blocks.
    ru_v4_opencck = _restrict_to_ipverse(ru_v4_opencck_raw, ru_v4_ipverse)
    ru_v6_opencck = _restrict_to_ipverse(ru_v6_opencck_raw, ru_v6_ipverse)
    skipped_v4 = len(ru_v4_opencck_raw) - len(ru_v4_opencck)
    skipped_v6 = len(ru_v6_opencck_raw) - len(ru_v6_opencck)
    if ru_v4_opencck_raw or ru_v6_opencck_raw:
        print(
            f"filter_ru: [2/2] opencck restricted to RIPE-RU: "
            f"v4={len(ru_v4_opencck)} (skipped {skipped_v4} non-RU CDN/global) "
            f"v6={len(ru_v6_opencck)} (skipped {skipped_v6})"
        )

    sources_meta.append(
        {
            "repo": RU_OPENCCK_REPO,
            "v4_url": RU_OPENCCK_V4_URL,
            "v6_url": RU_OPENCCK_V6_URL,
            "v4_raw_prefix_count": len(ru_v4_opencck_raw),
            "v6_raw_prefix_count": len(ru_v6_opencck_raw),
            "v4_prefix_count": len(ru_v4_opencck),
            "v6_prefix_count": len(ru_v6_opencck),
            "v4_skipped_outside_ripe_ru": skipped_v4,
            "v6_skipped_outside_ripe_ru": skipped_v6,
            "status": opencck_status,
            "restriction": "fully-within-ipverse-ru-only",
        }
    )

    # Union both sources, deduplicate by canonical CIDR string.
    ru_v4_seen: dict[str, ipaddress.IPv4Network] = {}
    for n in ru_v4_ipverse + ru_v4_opencck:
        ru_v4_seen[str(n)] = n
    ru_v6_seen: dict[str, ipaddress.IPv6Network] = {}
    for n in ru_v6_ipverse + ru_v6_opencck:
        ru_v6_seen[str(n)] = n
    ru_v4 = list(ru_v4_seen.values())
    ru_v6 = list(ru_v6_seen.values())
    print(
        f"filter_ru: union v4={len(ru_v4)} (ipverse={len(ru_v4_ipverse)}"
        f" + opencck={len(ru_v4_opencck)} - dupes)"
        f" v6={len(ru_v6)} (ipverse={len(ru_v6_ipverse)}"
        f" + opencck={len(ru_v6_opencck)} - dupes)"
    )

    new_snap, report = filter_snapshot(snap, ru_v4, ru_v6, sources_meta)

    out_bytes = (
        json.dumps(new_snap, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    write_atomic(out_path, out_bytes)

    digest = hashlib.sha256(out_bytes).hexdigest()
    write_atomic(sum_path, digest + "\n")

    rep_bytes = (
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    write_atomic(rep_path, rep_bytes)

    t = report["totals"]
    print(
        "filter_ru: done"
        f" services_touched={t['services_touched']}"
        f" v4_removed_prefixes={t['v4_removed_prefix_count']}"
        f" v6_removed_prefixes={t['v6_removed_prefix_count']}"
        f" v4_addresses={t['v4_addresses_removed']}"
        f" v6_addresses={t['v6_addresses_removed']}"
        f" sha256={digest}"
        f" size={len(out_bytes)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
