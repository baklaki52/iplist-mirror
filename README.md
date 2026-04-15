# iplist-mirror

Daily-refreshed aggregated CIDR snapshot of the
[rekryt/iplist](https://github.com/rekryt/iplist) service catalog,
fetched via [iplist.opencck.org](https://iplist.opencck.org) and
re-published as a single JSON document for
[kvn-vpn](https://github.com/baklaki52/kvn-vpn).

## What's here

- `snapshot.json` — current merged catalog (`schema_version=1`)
- `snapshot.sha256` — SHA-256 checksum of `snapshot.json` (hex)
- Git tags `vYYYYMMDD` — immutable daily snapshots
- `.github/workflows/daily-fetch.yml` — scheduled fetcher
- `scripts/fetch.sh` — single-step fetch + normalize + checksum

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
4. If nothing changed vs. previous snapshot — no-op (no empty commits).
5. Otherwise commits `snapshot.json` + `snapshot.sha256`, tags `vYYYYMMDD`,
   pushes both.

Concurrency group `daily-fetch` prevents parallel runs.

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
