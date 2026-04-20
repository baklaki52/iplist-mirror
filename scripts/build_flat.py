#!/usr/bin/env python3
"""build_flat.py — derive a flat slug→CIDR map from the snapshots.

Some consumers want a compact dict keyed by the service's primary
domain instead of walking through the full `services[]` array.

Input (produced by fetch.sh / filter_ru.py):

    { "services": [
        { "slug": "telegram.org", "domains": ["telegram.org", "t.me", ...],
          "cidr4": ["1.2.3.0/24"], "cidr6": ["2001::/32"], ... }
      ] }

Output:

    { "telegram.org": ["1.2.3.0/24", "2001::/32"],
      "whatsapp.com": ["1.2.3.0/24", "2001::/32"] }

Sub-hosts (t.me, core.telegram.org, …) are intentionally not enumerated
as separate keys: they share the same CIDR pool as the service's primary
domain, and a host that resolves into any of these CIDRs matches the
same route. One key per service is enough.

This script produces two derived files alongside the snapshots:

    snapshot.json            → by-slug.json
    snapshot-ru-clean.json   → by-slug-ru-clean.json

Rules:
  - Key is `service.slug` (for ~195 of 201 services it's a `domain.tld` pair).
  - Value is `cidr4 ∪ cidr6`, deduplicated and sorted.
  - Services with no CIDRs are skipped (no-value entry).
  - Services with no slug (rare) are skipped.
  - Output sorted by key for stable diffs.

Stdlib only. Non-fatal if a source snapshot is missing — that derived
file is simply not produced.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PAIRS = [
    ("snapshot.json", "by-slug.json"),
    ("snapshot-ru-clean.json", "by-slug-ru-clean.json"),
]


def build_one(src: Path, dst: Path) -> tuple[int, int]:
    """Return (service_count, total_cidr_count). Raises if src malformed."""
    data = json.loads(src.read_text())
    services = data.get("services", [])
    if not isinstance(services, list):
        raise ValueError(f"{src.name}: services[] missing or wrong type")

    out: dict[str, list[str]] = {}
    for svc in services:
        slug = (svc.get("slug") or "").strip()
        if not slug:
            continue
        cidr4 = svc.get("cidr4") or []
        cidr6 = svc.get("cidr6") or []
        cidrs = sorted(set(cidr4) | set(cidr6))
        if not cidrs:
            continue
        # Collision is unusual (slug is upstream's primary key) but handle
        # it defensively by union-merging.
        if slug in out:
            out[slug] = sorted(set(out[slug]) | set(cidrs))
        else:
            out[slug] = cidrs

    final = {k: out[k] for k in sorted(out)}

    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_text(
        json.dumps(final, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    tmp.replace(dst)

    digest = hashlib.sha256(dst.read_bytes()).hexdigest()
    dst.with_suffix(dst.suffix + ".sha256").write_text(digest + "\n")

    total_cidrs = sum(len(v) for v in final.values())
    return (len(final), total_cidrs)


def main() -> int:
    any_built = False
    for src_name, dst_name in PAIRS:
        src = ROOT / src_name
        dst = ROOT / dst_name
        if not src.exists():
            print(f"skip: {src_name} missing")
            continue
        try:
            services, cidrs = build_one(src, dst)
        except Exception as e:
            print(f"FAIL: {src_name} → {dst_name}: {e}", file=sys.stderr)
            continue
        print(f"ok:   {dst_name} services={services} cidrs={cidrs}")
        any_built = True

    if not any_built:
        print("no inputs found — nothing built", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
