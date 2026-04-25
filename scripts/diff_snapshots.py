#!/usr/bin/env python3
"""diff_snapshots.py — structured diff between two snapshot.json revisions.

Prints what's added/removed at the CIDR level, per-service deltas,
ASN-overlay changes, ru_filter source changes, and a health-check pass
for critical IPs that must stay covered (Gemini, YouTube, OpenAI,
Telegram, etc).

Usage:
    diff_snapshots.py <BEFORE> <AFTER>

Both args can be:
    - file path     (e.g. ./snapshot.json or /tmp/old.json)
    - git ref       (e.g. HEAD~1, main, v20260424, 5029906)
    - git ref:path  (e.g. main:snapshot.json — explicit when default differs)

Default file looked up in a git ref is `snapshot-ru-clean.json` because
that's what split-tunnel consumers actually read. Override with
--file=snapshot.json for the unfiltered comparison.

Examples:
    # Compare today's CI snapshot to yesterday's tagged release
    ./scripts/diff_snapshots.py v20260424 main

    # Sanity-check before a PR is merged: local working-tree vs main
    bash scripts/fetch.sh && ./scripts/diff_snapshots.py main: ./snapshot-ru-clean.json

    # Compare against the snapshot you remember was good
    ./scripts/diff_snapshots.py 5029906 HEAD

Exit codes:
    0 = identical or only additions (safe)
    1 = removals OR critical IP regression detected
    2 = bad arguments / unable to load snapshots

Stdlib only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Critical IPs that MUST stay covered after any pipeline change.
# Adding new entries here turns regressions into automatic CI fails.
# Format: (label, ip_address). Resolve via DNS before adding to capture
# the actual IPs your service uses today (DNS results change over time —
# pin the literal that broke historically, not the domain).
CRITICAL_IPS = [
    # Google AI Studio — broke in PR #2 because opencck-russia included
    # 142.250.0.0/16 as RU. Lives in 142.250.0.0/15.
    ("Gemini (aistudio.google.com)",   "142.251.209.238"),
    # YouTube googlevideo edge — same Google /15 family.
    ("YouTube googlevideo",            "142.250.185.78"),
    # OpenAI ChatGPT — Cloudflare-fronted (104.x), at risk if anyone
    # ever subtracts Cloudflare blocks.
    ("OpenAI ChatGPT",                 "104.18.32.47"),
    # Anthropic Claude — Cloudflare too.
    ("Anthropic Claude",               "104.18.34.47"),
    # Telegram main DC — should stay covered via messengers + ASN overlay.
    ("Telegram DC4",                   "149.154.167.50"),
    # Telegram media CDN — was the original PR #2 motivation.
    ("Telegram media-CDN",             "91.108.56.165"),
    # Discord gateway — voice ASN overlay covers voice; gateway is on
    # Cloudflare so this tests the broad CDN coverage too.
    ("Discord gateway",                "162.159.135.232"),
]


def load_snapshot(spec: str, default_filename: str) -> dict:
    """Load snapshot from a file path or a git ref. Returns parsed dict."""
    # Explicit ref:path syntax (`main:snapshot.json`)
    if ":" in spec and not spec.startswith("/"):
        ref, path = spec.split(":", 1)
        return _load_from_git(ref or "HEAD", path or default_filename)

    p = Path(spec)
    if p.exists() and p.is_file():
        return json.loads(p.read_text())

    # Treat as git ref
    return _load_from_git(spec, default_filename)


def _load_from_git(ref: str, path: str) -> dict:
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"FAIL: cannot read git ref {ref}:{path}\n  stderr: {exc.stderr.strip()}"
        )
    return json.loads(result.stdout)


def _all_v4(snap: dict) -> set:
    return {c for s in snap.get("services", []) for c in s.get("cidr4", [])}


def _all_v6(snap: dict) -> set:
    return {c for s in snap.get("services", []) for c in s.get("cidr6", [])}


def _by_slug(snap: dict) -> dict:
    return {s["slug"]: s for s in snap.get("services", [])}


def _check_ip(ip: str, snap: dict, family: int = 4):
    """Return (covered_by_slug, covered_by_cidr) or (None, None)."""
    try:
        ip_o = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    field = "cidr4" if family == 4 else "cidr6"
    for svc in snap.get("services", []):
        for cidr in svc.get(field, []):
            try:
                if ip_o in ipaddress.ip_network(cidr, strict=False):
                    return svc["slug"], cidr
            except ValueError:
                continue
    return None, None


def _aggregate_size(cidrs: set) -> int:
    """Sum of unique addresses covered (both v4 and v6 strings allowed)."""
    total = 0
    for c in cidrs:
        try:
            total += ipaddress.ip_network(c, strict=False).num_addresses
        except ValueError:
            pass
    return total


def diff(before: dict, after: dict) -> tuple[int, list[str]]:
    """Return (exit_code, lines)."""
    out: list[str] = []
    exit_code = 0

    bv4 = _all_v4(before)
    av4 = _all_v4(after)
    bv6 = _all_v6(before)
    av6 = _all_v6(after)

    removed_v4 = bv4 - av4
    added_v4 = av4 - bv4
    removed_v6 = bv6 - av6
    added_v6 = av6 - bv6

    out.append("══════════════ SNAPSHOT DIFF ══════════════")
    out.append(f"  before generated_at: {before.get('generated_at', '?')}")
    out.append(f"  after  generated_at: {after.get('generated_at', '?')}")
    out.append(f"  before source_tag:   {before.get('source_tag', '?')}")
    out.append(f"  after  source_tag:   {after.get('source_tag', '?')}")
    out.append("")
    out.append("─── totals ───")
    out.append(
        f"  v4 CIDRs (unique): before={len(bv4):>5}  after={len(av4):>5}  "
        f"Δ={len(av4)-len(bv4):+}"
    )
    out.append(
        f"  v6 CIDRs (unique): before={len(bv6):>5}  after={len(av6):>5}  "
        f"Δ={len(av6)-len(bv6):+}"
    )

    bv4_addrs = _aggregate_size(bv4)
    av4_addrs = _aggregate_size(av4)
    out.append(
        f"  v4 address coverage: before={bv4_addrs:>14,}  after={av4_addrs:>14,}  "
        f"Δ={av4_addrs-bv4_addrs:+,}"
    )

    out.append("")
    out.append(f"─── removed (only in BEFORE): v4={len(removed_v4)} v6={len(removed_v6)} ───")
    if removed_v4:
        exit_code = max(exit_code, 1)
        # Sort by network size first (broader = more impactful)
        sortable = []
        for c in removed_v4:
            try:
                n = ipaddress.ip_network(c, strict=False)
                sortable.append((n.prefixlen, str(n)))
            except ValueError:
                pass
        sortable.sort()  # /8 first → /32 last
        for _, c in sortable[:25]:
            out.append(f"  - {c}")
        if len(sortable) > 25:
            out.append(f"  ... +{len(sortable) - 25} more")

    out.append("")
    out.append(f"─── added (only in AFTER): v4={len(added_v4)} v6={len(added_v6)} ───")
    if added_v4:
        sortable = []
        for c in added_v4:
            try:
                n = ipaddress.ip_network(c, strict=False)
                sortable.append((n.prefixlen, str(n)))
            except ValueError:
                pass
        sortable.sort()
        for _, c in sortable[:25]:
            out.append(f"  + {c}")
        if len(sortable) > 25:
            out.append(f"  ... +{len(sortable) - 25} more")

    # Per-service deltas
    out.append("")
    out.append("─── per-service v4 count delta ───")
    bs = _by_slug(before)
    as_ = _by_slug(after)
    deltas = []
    for slug in sorted(set(bs) | set(as_)):
        bn = len(bs[slug]["cidr4"]) if slug in bs else 0
        an = len(as_[slug]["cidr4"]) if slug in as_ else 0
        if bn != an:
            deltas.append((slug, bn, an, an - bn))
    deltas.sort(key=lambda x: abs(x[3]), reverse=True)
    if not deltas:
        out.append("  (no service-level changes)")
    else:
        out.append(f"  {len(deltas)} service(s) changed:")
        for slug, bn, an, d in deltas[:30]:
            mark = "  "
            if slug not in as_:
                mark = "✗ "  # entirely dropped
            elif slug not in bs:
                mark = "+ "  # entirely new
            out.append(f"  {mark}{slug:35}  before={bn:>5}  after={an:>5}  Δ={d:+}")
        if len(deltas) > 30:
            out.append(f"  ... +{len(deltas) - 30} more")

    # ASN overlay block diff
    out.append("")
    out.append("─── asn_overlay diff ───")
    b_asn = before.get("asn_overlay", {}).get("entries", [])
    a_asn = after.get("asn_overlay", {}).get("entries", [])
    b_asn_map = {e["slug"]: e for e in b_asn}
    a_asn_map = {e["slug"]: e for e in a_asn}
    for slug in sorted(set(b_asn_map) | set(a_asn_map)):
        bn = b_asn_map.get(slug, {}).get("v4_total", 0)
        an = a_asn_map.get(slug, {}).get("v4_total", 0)
        b_asns = b_asn_map.get(slug, {}).get("asns", [])
        a_asns = a_asn_map.get(slug, {}).get("asns", [])
        if bn != an or b_asns != a_asns:
            mark = "+ " if slug not in b_asn_map else ("✗ " if slug not in a_asn_map else "  ")
            out.append(f"  {mark}{slug:25}  v4: {bn} → {an}   asns: {b_asns} → {a_asns}")
    if not (set(b_asn_map) ^ set(a_asn_map)) and all(
        b_asn_map[k].get("v4_total", 0) == a_asn_map[k].get("v4_total", 0)
        for k in set(b_asn_map) & set(a_asn_map)
    ):
        out.append("  (unchanged)")

    # ru_filter sources diff
    out.append("")
    out.append("─── ru_filter sources diff ───")
    b_rf = before.get("ru_filter", {}).get("sources", [])
    a_rf = after.get("ru_filter", {}).get("sources", [])
    if not b_rf and "source" in before.get("ru_filter", {}):
        # Legacy single-source schema
        b_rf = [{
            "repo": before["ru_filter"].get("source", "?"),
            "v4_prefix_count": before["ru_filter"].get("ru_v4_prefix_count", 0),
        }]
    b_repos = {s["repo"] for s in b_rf}
    a_repos = {s["repo"] for s in a_rf}
    for repo in sorted(b_repos | a_repos):
        b_count = next((s.get("v4_prefix_count", 0) for s in b_rf if s.get("repo") == repo), None)
        a_count = next((s.get("v4_prefix_count", 0) for s in a_rf if s.get("repo") == repo), None)
        a_skipped = next((s.get("v4_skipped_outside_ripe_ru") for s in a_rf if s.get("repo") == repo), None)
        if b_count is None:
            out.append(f"  + {repo:35}  v4={a_count} (NEW source)")
        elif a_count is None:
            out.append(f"  ✗ {repo:35}  v4={b_count} (REMOVED source)")
        elif b_count != a_count or a_skipped is not None:
            extra = f"  skipped={a_skipped}" if a_skipped is not None else ""
            out.append(f"    {repo:35}  v4: {b_count} → {a_count}{extra}")

    # Critical IP health-check
    out.append("")
    out.append("─── critical IP health-check ───")
    any_regression = False
    for label, ip in CRITICAL_IPS:
        b_slug, b_cidr = _check_ip(ip, before)
        a_slug, a_cidr = _check_ip(ip, after)
        if a_slug is None:
            mark = "❌ REGRESSION" if b_slug else "⚠️  not covered (was already not covered)"
            if b_slug:
                any_regression = True
                exit_code = max(exit_code, 1)
            out.append(f"  {mark}  {label:42}  {ip}")
            if b_slug:
                out.append(f"      was covered by {b_slug}: {b_cidr}")
        elif b_slug is None:
            out.append(f"  ✅ NEW COVERAGE   {label:42}  {ip}  via {a_slug}: {a_cidr}")
        elif a_cidr != b_cidr:
            out.append(f"  ✅ STILL COVERED  {label:42}  {ip}  via {a_slug}: {a_cidr}  (was {b_cidr})")
        else:
            out.append(f"  ✅ STILL COVERED  {label:42}  {ip}  via {a_slug}: {a_cidr}")

    out.append("")
    if exit_code == 0:
        out.append("VERDICT: ✅ no regression detected")
    else:
        out.append("VERDICT: ❌ regression — see removed CIDRs and critical IP block above")

    return exit_code, out


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Structured diff between two snapshot.json revisions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:", 1)[1] if "Usage:" in __doc__ else "",
    )
    p.add_argument("before", help="git ref or file path of the BEFORE snapshot")
    p.add_argument("after", help="git ref or file path of the AFTER snapshot")
    p.add_argument(
        "--file",
        default="snapshot-ru-clean.json",
        help="default filename to look up inside a git ref (default: snapshot-ru-clean.json)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    args = p.parse_args(argv)

    before = load_snapshot(args.before, args.file)
    after = load_snapshot(args.after, args.file)

    if args.json:
        bv4 = _all_v4(before)
        av4 = _all_v4(after)
        report = {
            "before": {"generated_at": before.get("generated_at"), "v4": len(bv4)},
            "after": {"generated_at": after.get("generated_at"), "v4": len(av4)},
            "removed_v4": sorted(bv4 - av4),
            "added_v4": sorted(av4 - bv4),
            "critical_ip_check": [],
        }
        for label, ip in CRITICAL_IPS:
            b_slug, b_cidr = _check_ip(ip, before)
            a_slug, a_cidr = _check_ip(ip, after)
            report["critical_ip_check"].append(
                {
                    "label": label,
                    "ip": ip,
                    "before": {"slug": b_slug, "cidr": b_cidr},
                    "after": {"slug": a_slug, "cidr": a_cidr},
                    "regression": (b_slug is not None and a_slug is None),
                }
            )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        ec = 0
        if any(c["regression"] for c in report["critical_ip_check"]) or report["removed_v4"]:
            ec = 1
        return ec

    ec, lines = diff(before, after)
    print("\n".join(lines))
    return ec


if __name__ == "__main__":
    raise SystemExit(main())
