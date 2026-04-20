#!/usr/bin/env python3
"""build_flat.py — derive compact flat formats from the snapshots.

Two output families are produced for each input snapshot:

    snapshot.json            → by-slug.json          (dict: slug → CIDR list)
    snapshot.json            → all-cidrs.json        (flat list of all CIDR)
    snapshot-ru-clean.json   → by-slug-ru-clean.json
    snapshot-ru-clean.json   → all-cidrs-ru-clean.json

`by-slug.*` — dict keyed by service primary domain (one key per service,
value is cidr4 ∪ cidr6, deduplicated and sorted). Good when consumer
wants to know which service a prefix belongs to.

`all-cidrs.*` — flat JSON array of every CIDR across every service,
deduplicated and sorted. Good when consumer only needs the union of
prefixes (e.g. routing tables, split-tunneling allowlists) and doesn't
care about per-service breakdown — some importers expect the root
element to be an array, not an object.

Rules:
  - `slug` is the key in `by-slug.*` (for ~195 of 201 services it's a
    `domain.tld` pair).
  - Value is `cidr4 ∪ cidr6`, deduplicated.
  - Services with no CIDRs are skipped.
  - Services with no slug are skipped.
  - Outputs sorted for stable diffs.

Stdlib only. Non-fatal if a source snapshot is missing — that derived
file is simply not produced.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCES = [
    ("snapshot.json", "by-slug.json", "all-cidrs.json"),
    ("snapshot-ru-clean.json", "by-slug-ru-clean.json", "all-cidrs-ru-clean.json"),
]


def write_json(dst: Path, payload) -> None:
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    tmp.replace(dst)
    digest = hashlib.sha256(dst.read_bytes()).hexdigest()
    dst.with_suffix(dst.suffix + ".sha256").write_text(digest + "\n")


def build_one(src: Path, by_slug_dst: Path, flat_dst: Path) -> tuple[int, int, int]:
    """Return (service_count, by_slug_cidr_sum, flat_cidr_count)."""
    data = json.loads(src.read_text())
    services = data.get("services", [])
    if not isinstance(services, list):
        raise ValueError(f"{src.name}: services[] missing or wrong type")

    by_slug: dict[str, set[str]] = {}
    all_cidrs: set[str] = set()
    for svc in services:
        slug = (svc.get("slug") or "").strip()
        cidr4 = svc.get("cidr4") or []
        cidr6 = svc.get("cidr6") or []
        cidrs = set(cidr4) | set(cidr6)
        if not cidrs:
            continue
        all_cidrs.update(cidrs)
        if not slug:
            continue
        if slug in by_slug:
            by_slug[slug] |= cidrs
        else:
            by_slug[slug] = set(cidrs)

    by_slug_final = {k: sorted(by_slug[k]) for k in sorted(by_slug)}
    all_cidrs_final = sorted(all_cidrs)

    write_json(by_slug_dst, by_slug_final)
    write_json(flat_dst, all_cidrs_final)

    by_slug_sum = sum(len(v) for v in by_slug_final.values())
    return (len(by_slug_final), by_slug_sum, len(all_cidrs_final))


def main() -> int:
    any_built = False
    for src_name, by_slug_name, flat_name in SOURCES:
        src = ROOT / src_name
        if not src.exists():
            print(f"skip: {src_name} missing")
            continue
        try:
            services, by_slug_sum, flat_count = build_one(
                src, ROOT / by_slug_name, ROOT / flat_name
            )
        except Exception as e:
            print(f"FAIL: {src_name}: {e}", file=sys.stderr)
            continue
        print(
            f"ok:   {by_slug_name:28s} services={services} cidr_sum={by_slug_sum}"
        )
        print(f"ok:   {flat_name:28s} unique_cidrs={flat_count}")
        any_built = True

    if not any_built:
        print("no inputs found — nothing built", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
