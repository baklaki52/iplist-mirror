#!/usr/bin/env bash
# fetch.sh — builds snapshot.json + snapshot.sha256 from iplist.opencck.org.
#
# iplist.opencck.org quirks (verified 2026-04-14):
# - Each ?data= param returns a map {service_slug: [values...]}.
# - Requesting multiple ?data= params concatenates VALUES into one array,
#   losing type info. We therefore issue 4 separate requests per category
#   (cidr4, cidr6, domains, dns) and zip them client-side.
# - Empty categories return "{}" (2 bytes) — tolerated, not an error.
#
# Behaviour:
# - 17 categories from upstream (sorted by slug).
# - Per-request: 3 retries × 60s timeout; failure aborts (no partial snapshot).
# - Merges into snapshot.json at schema_version=1, services sorted by slug.
# - Emits snapshot.sha256 (hex only, no filename).
#
# Requires: bash, curl, jq, sha256sum (Linux) or shasum (macOS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CATEGORIES=(
  tools search news video youtube socials
  messengers music shop education art anime
  games jetbrains discord torrent porn
)
DATA_KINDS=(cidr4 cidr6 domains dns)

BASE="https://iplist.opencck.org"
UA="iplist-mirror-bot/1.0 (+https://github.com/baklaki52/iplist-mirror)"
RAW_DIR="$(mktemp -d)"
SERVICES_TMP="$(mktemp)"
trap 'rm -rf "$RAW_DIR" "$SERVICES_TMP"' EXIT

fetch_one() {
  local cat="$1" kind="$2" out="$3"
  local url="${BASE}/?format=json&group=${cat}&data=${kind}"
  local attempt
  for attempt in 1 2 3; do
    if curl -sfL --max-time 60 -A "$UA" "$url" -o "$out"; then
      return 0
    fi
    echo "  retry ${cat}/${kind} attempt=${attempt}" >&2
    sleep 5
  done
  return 1
}

echo "fetch: ${#CATEGORIES[@]} categories × ${#DATA_KINDS[@]} data kinds"
for cat in "${CATEGORIES[@]}"; do
  for kind in "${DATA_KINDS[@]}"; do
    out="${RAW_DIR}/${cat}.${kind}.json"
    if ! fetch_one "$cat" "$kind" "$out"; then
      echo "FAIL: ${cat}/${kind} unreachable after 3 attempts" >&2
      exit 1
    fi
  done
  echo "  ok  ${cat}"
done

echo "normalize:"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TAG="v$(date -u +%Y%m%d)"

# For each category, collect union of service slugs across 4 data kinds, then
# build a record per service by looking up each kind (defaulting to []).
: >"$SERVICES_TMP"
for cat in "${CATEGORIES[@]}"; do
  c4="${RAW_DIR}/${cat}.cidr4.json"
  c6="${RAW_DIR}/${cat}.cidr6.json"
  dn="${RAW_DIR}/${cat}.domains.json"
  ds="${RAW_DIR}/${cat}.dns.json"
  jq -n --arg cat "$cat" \
    --slurpfile c4 "$c4" \
    --slurpfile c6 "$c6" \
    --slurpfile dn "$dn" \
    --slurpfile ds "$ds" \
    '
      ($c4[0] // {}) as $C4 |
      ($c6[0] // {}) as $C6 |
      ($dn[0] // {}) as $DN |
      ($ds[0] // {}) as $DS |
      [($C4, $C6, $DN, $DS) | keys[]] | unique
      | map({
          slug:     (. | ascii_downcase),
          name:     .,
          category: $cat,
          cidr4:    ($C4[.] // []),
          cidr6:    ($C6[.] // []),
          domains:  ($DN[.] // []),
          dns:      ($DS[.] // [])
        })
      | .[]
    ' >>"$SERVICES_TMP"
done

# Merge all per-category records into one sorted array. Use a file + slurpfile
# (not --argjson) because the JSON easily exceeds argv length limits.
SORTED_TMP="$(mktemp)"
trap 'rm -rf "$RAW_DIR" "$SERVICES_TMP" "$SORTED_TMP"' EXIT
jq -s 'sort_by(.slug)' "$SERVICES_TMP" >"$SORTED_TMP"
count=$(jq 'length' "$SORTED_TMP")
if [ "$count" -lt 100 ]; then
  echo "FAIL: only ${count} services, expected >=100" >&2
  exit 1
fi

jq -n \
  --slurpfile services "$SORTED_TMP" \
  --arg gen "$GENERATED_AT" \
  --arg tag "$TAG" \
  '{
    schema_version: 1,
    generated_at:   $gen,
    source:         "rekryt/iplist via iplist.opencck.org",
    source_tag:     $tag,
    services:       $services[0]
  }' >snapshot.json.tmp
mv snapshot.json.tmp snapshot.json

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum snapshot.json | awk '{print $1}' >snapshot.sha256
else
  shasum -a 256 snapshot.json | awk '{print $1}' >snapshot.sha256
fi

echo "done: services=${count} sha256=$(cat snapshot.sha256) size=$(wc -c <snapshot.json | tr -d ' ')"

# ASN overlay: inject BGP-truth CIDRs for services where DNS-based discovery
# misses direct DC subnets (Telegram primarily). Runs BEFORE filter_ru so the
# RU-clean snapshot also benefits, and AFTER fetch so the base snapshot is
# already on disk. Non-fatal: missing bgpq4 or fetch failure leaves snapshot
# untouched.
if command -v python3 >/dev/null 2>&1; then
  if command -v bgpq4 >/dev/null 2>&1; then
    echo "asn-overlay:"
    if ! python3 scripts/asn_overlay.py; then
      echo "WARN: asn_overlay.py exited non-zero — proceeding with un-augmented snapshot" >&2
    fi
  else
    echo "WARN: bgpq4 not installed — skipping ASN overlay (Telegram-DC subnets may be incomplete)" >&2
  fi

  # Build snapshot-ru-clean.json by subtracting RU country CIDRs.
  # Sources: ipverse/rir-ip (RIPE country-allocated) ∪ russia.iplist.opencck.org
  # (curated 77 RU services). Union catches both RU-allocated and foreign-IP
  # RU services.
  # Non-fatal: filter_ru.py exits 0 on upstream fetch failure leaving prior
  # clean snapshot in place, so the unfiltered snapshot still ships.
  echo "ru-filter:"
  if ! python3 scripts/filter_ru.py; then
    echo "WARN: filter_ru.py exited non-zero — snapshot.json still published" >&2
  fi
  # Derive the flat slug → CIDR map ({slug: [cidrs...]}).
  # Consumes both snapshot.json and snapshot-ru-clean.json if present.
  echo "build-flat:"
  if ! python3 scripts/build_flat.py; then
    echo "WARN: build_flat.py exited non-zero — derived files may be stale" >&2
  fi
else
  echo "WARN: python3 not found — skipping snapshot-ru-clean & flat derivatives" >&2
fi

# No-op detection (only meaningful inside a git worktree).
if git rev-parse --git-dir >/dev/null 2>&1; then
  TRACKED_FILES="snapshot.json snapshot.sha256 snapshot-ru-clean.json snapshot-ru-clean.sha256 ru_filter_report.json by-slug.json by-slug.json.sha256 by-slug-ru-clean.json by-slug-ru-clean.json.sha256 all-cidrs.json all-cidrs.json.sha256 all-cidrs-ru-clean.json all-cidrs-ru-clean.json.sha256"
  if git diff --quiet -- $TRACKED_FILES 2>/dev/null; then
    echo "no-op: snapshot unchanged vs HEAD"
  fi
fi
