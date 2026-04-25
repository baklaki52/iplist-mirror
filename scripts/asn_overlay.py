#!/usr/bin/env python3
"""asn_overlay.py — inject BGP-truth CIDRs into snapshot.json for services
where DNS-based discovery (rekryt/iplist) misses direct DC subnets.

Why:
  rekryt collects CIDRs by resolving thousands of public domains. Telegram
  uses dedicated DC subnets that don't appear in any *.telegram.org A-record
  (e.g. 91.108.36.0/23, 95.161.84.0/22). Clients miss them, traffic falls
  back to the local ISP, and inside RU it gets blocked / shaped.

  We pull the canonical ASN-block list with bgpq4 and merge it into the
  service's cidr4/cidr6 lists. Idempotent: re-running is a no-op.

Strategy:
  Pure additive overlay — never removes upstream CIDRs, only adds missing
  ones. Subnet collision check uses ipaddress.IPv4Network.subnet_of(): we
  drop a fresh prefix that's already fully covered by an existing one,
  but keep equal/orthogonal additions. Aggregation runs at build_flat
  stage, not here.

Failure mode:
  If bgpq4 fails or returns suspiciously few prefixes (< MIN_EXPECTED),
  the script exits 0 without modifying snapshot.json. Stale-but-correct
  beats partial-and-broken.

Stdlib only (subprocess for bgpq4).
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "snapshot.json"

# Per-service ASN overlay config.
# Each entry: { slug, category, asns, min_expected_v4, min_expected_v6 }.
# `slug` and `category` must match an existing entry in snapshot.json — we
# augment it. (If the slug is missing, we create a fresh service record.)
OVERLAYS = [
    {
        "slug": "telegram.org",
        "category": "messengers",
        "asns": ["AS62041", "AS59930", "AS44907", "AS211157", "AS62014"],
        # bgpq4 currently returns ~29 v4 prefixes; alarm if it drops below.
        "min_expected_v4": 10,
        "min_expected_v6": 0,
    },
]

BGPQ4_TIMEOUT = 60


def run_bgpq4(asns: list[str], family: int) -> list[str]:
    """Return list of CIDR strings for given ASNs. [] on failure."""
    flag = "-4" if family == 4 else "-6"
    cmd = ["bgpq4", flag, "-F", "%n/%l\n", *asns]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=BGPQ4_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"  bgpq4 failed: {exc}", file=sys.stderr)
        return []
    if result.returncode != 0:
        print(
            f"  bgpq4 rc={result.returncode} stderr={result.stderr.strip()}",
            file=sys.stderr,
        )
        return []
    out = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            if (family == 4 and isinstance(net, ipaddress.IPv4Network)) or (
                family == 6 and isinstance(net, ipaddress.IPv6Network)
            ):
                out.append(str(net))
        except ValueError:
            continue
    return out


def merge_cidrs(existing: list[str], fresh: list[str], family: int) -> tuple[list[str], int]:
    """Add `fresh` CIDRs to `existing`, skipping any fully covered. Returns
    (merged_sorted, added_count)."""
    net_cls = ipaddress.IPv4Network if family == 4 else ipaddress.IPv6Network
    existing_nets = []
    for c in existing:
        try:
            existing_nets.append(net_cls(c, strict=False))
        except ValueError:
            continue
    seen = {str(n) for n in existing_nets}
    added = 0
    for c in fresh:
        try:
            n = net_cls(c, strict=False)
        except ValueError:
            continue
        if str(n) in seen:
            continue
        # Skip if already fully covered by a broader existing prefix.
        if any(n.subnet_of(e) for e in existing_nets):
            continue
        existing_nets.append(n)
        seen.add(str(n))
        added += 1
    merged_sorted = sorted({str(n) for n in existing_nets})
    return merged_sorted, added


def find_service(services: list[dict], slug: str) -> dict | None:
    for svc in services:
        if svc.get("slug") == slug:
            return svc
    return None


def main() -> int:
    if not SNAPSHOT.exists():
        print(f"FAIL: {SNAPSHOT} missing", file=sys.stderr)
        return 1
    data = json.loads(SNAPSHOT.read_text())
    services = data.get("services", [])
    if not services:
        print("FAIL: snapshot has no services", file=sys.stderr)
        return 1

    overlay_meta = []
    total_added_v4 = 0
    total_added_v6 = 0
    for cfg in OVERLAYS:
        slug = cfg["slug"]
        asns = cfg["asns"]
        print(f"asn_overlay: {slug} ← {' '.join(asns)}")

        v4 = run_bgpq4(asns, 4)
        v6 = run_bgpq4(asns, 6)
        if len(v4) < cfg.get("min_expected_v4", 0):
            print(
                f"  WARN: only {len(v4)} v4 prefixes (need >={cfg['min_expected_v4']}) — skip",
                file=sys.stderr,
            )
            continue
        if cfg.get("min_expected_v6", 0) and len(v6) < cfg["min_expected_v6"]:
            print(
                f"  WARN: only {len(v6)} v6 prefixes (need >={cfg['min_expected_v6']}) — skip",
                file=sys.stderr,
            )
            continue

        svc = find_service(services, slug)
        if svc is None:
            # Create a fresh service record sourced purely from BGP.
            svc = {
                "slug": slug,
                "name": slug,
                "category": cfg["category"],
                "cidr4": [],
                "cidr6": [],
                "domains": [],
                "dns": [],
            }
            services.append(svc)
            services.sort(key=lambda s: s.get("slug", ""))
            print(f"  created new service {slug}")

        merged_v4, added_v4 = merge_cidrs(svc.get("cidr4", []), v4, 4)
        merged_v6, added_v6 = merge_cidrs(svc.get("cidr6", []), v6, 6)
        svc["cidr4"] = merged_v4
        svc["cidr6"] = merged_v6
        total_added_v4 += added_v4
        total_added_v6 += added_v6

        overlay_meta.append(
            {
                "slug": slug,
                "asns": asns,
                "v4_added": added_v4,
                "v6_added": added_v6,
                "v4_total": len(merged_v4),
                "v6_total": len(merged_v6),
            }
        )
        print(
            f"  {slug}: +{added_v4} v4, +{added_v6} v6 "
            f"(now {len(merged_v4)} v4, {len(merged_v6)} v6)"
        )

    if total_added_v4 == 0 and total_added_v6 == 0:
        print("asn_overlay: nothing to add — snapshot unchanged")
        return 0

    data["asn_overlay"] = {
        "applied_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "bgpq4",
        "entries": overlay_meta,
    }
    tmp = SNAPSHOT.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.replace(tmp, SNAPSHOT)
    print(
        f"asn_overlay: total +{total_added_v4} v4 / +{total_added_v6} v6 "
        f"across {len(overlay_meta)} service(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
