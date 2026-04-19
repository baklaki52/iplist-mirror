# iplist-mirror

Daily-refreshed aggregated CIDR snapshot of the
[rekryt/iplist](https://github.com/rekryt/iplist) service catalog,
fetched via [iplist.opencck.org](https://iplist.opencck.org) and
re-published as a single JSON document for
[kvn-vpn](https://github.com/baklaki52/kvn-vpn).

## What's here

- `snapshot.json` — current merged catalog (`schema_version=1`)
- `snapshot.sha256` — SHA-256 checksum of `snapshot.json` (hex)
- `snapshot-ru-clean.json` — same catalog with Russian-country CIDRs subtracted
  (see [RU filter](#ru-filter) below)
- `snapshot-ru-clean.sha256` — SHA-256 of the cleaned snapshot
- `ru_filter_report.json` — per-category / per-service breakdown of removals
- Git tags `vYYYYMMDD` — immutable daily snapshots
- `.github/workflows/daily-fetch.yml` — scheduled fetcher
- `scripts/fetch.sh` — single-step fetch + normalize + checksum
- `scripts/filter_ru.py` — RU-CIDR subtractor invoked by `fetch.sh`

## Schema

```json
{
  "schema_version": 1,
  "generated_at": "2026-04-15T03:00:00Z",
  "source": "rekryt/iplist via iplist.opencck.org",
  "source_tag": "v20260415",
  "services": [
    {
      "slug": "youtube",
      "name": "YouTube",
      "category": "youtube",
      "cidr4": ["142.250.0.0/15"],
      "cidr6": ["2a00::/16"],
      "domains": ["youtube.com"],
      "dns": ["8.8.8.8"]
    }
  ]
}
```

Services are sorted by `slug`. Categories mirror the 16 groups consumed by
kvn-vpn (`casino` excluded by policy).

## How it's built

GitHub Action `daily-fetch` runs at **03:00 UTC** daily (and on
`workflow_dispatch`):

1. Fetches 16 categories from `iplist.opencck.org`
   (`?format=json&group={cat}&data=cidr4&data=cidr6&data=domains&data=dns`).
2. Merges into `snapshot.json` at `schema_version=1`.
3. Computes `snapshot.sha256`.
4. Builds `snapshot-ru-clean.json` by subtracting Russian-country CIDRs
   (see [RU filter](#ru-filter)).
5. If nothing changed vs. previous snapshot — no-op (no empty commits).
6. Otherwise commits all changed files, tags `vYYYYMMDD`, pushes both.

Concurrency group `daily-fetch` prevents parallel runs.

## RU filter

Upstream catalog occasionally bundles Russian ISP CIDRs into service
categories where they don't belong (e.g. ~40 RU prefixes inside `youtube`
that stopped working when Google withdrew its in-country GGC nodes; Yandex
Cloud blocks under `art`; RU video CDN fragments under `anime`/`video`).
Routing those through a foreign-exit VPN is wasteful or outright broken.

`scripts/filter_ru.py` runs immediately after normalisation in the same CI
job and produces `snapshot-ru-clean.json`:

- **Source of truth for RU allocations:**
  [`ipverse/rir-ip`](https://github.com/ipverse/rir-ip) —
  RIPE-NCC-aggregated daily snapshots
  (`country/ru/ipv4-aggregated.txt`, `country/ru/ipv6-aggregated.txt`).
- **Operation:** strict CIDR set subtraction. A prefix that fully sits
  inside a RU block is dropped; a prefix that strictly contains a RU block
  is split via `ipaddress.IPv4Network.address_exclude` so non-RU territory
  is preserved. CIDR networks are by construction either disjoint, equal,
  or one fully contains the other — there is no partial-overlap case.
- **Schema delta:** `snapshot-ru-clean.json` adds an `ru_filter` block
  with the source URLs, RU prefix counts, and `applied_at` timestamp.
  All other fields are byte-identical to `snapshot.json`.
- **Audit:** `ru_filter_report.json` lists every removed prefix grouped
  by service and by category. Operators can diff it across `vYYYYMMDD`
  tags to see how the upstream catalog changes over time.
- **Failure mode:** if `ipverse/rir-ip` is unreachable, `filter_ru.py`
  exits 0 leaving the previous `snapshot-ru-clean.json` in place. The
  unfiltered `snapshot.json` always ships even when the filter is
  unavailable.

Consumers wanting the raw upstream catalog continue to read `snapshot.json`
unchanged. Consumers wanting cleaner AllowedIPs read
`snapshot-ru-clean.json` (verify against `snapshot-ru-clean.sha256`).

## Consumer

kvn-vpn fetches
`https://raw.githubusercontent.com/baklaki52/iplist-mirror/main/snapshot.json`
once per 24 h (with ETag conditional GET) and verifies SHA-256 via the sibling
`snapshot.sha256` file.

## Privacy note

Each update check reveals the consumer's IP to GitHub (similar to a browser
fetching a blocklist). Operators who prefer zero outbound can pin kvn-vpn to
the embedded snapshot shipped inside the binary
(`catalog.update_source: embed`).

## Source & License

- Upstream data: [rekryt/iplist](https://github.com/rekryt/iplist), MIT.
- This mirror's scripts: MIT (see `LICENSE`).
- Underlying catalog © rekryt contributors.
