# awg-bot consumer

Reference copy of the AmneziaWG Telegram-bot server scripts that consume this
mirror's `snapshot-ru-clean.json`. Lives here for backup/version-control —
the live copies run on the VPN servers (kvn, baton) in `/root/awg-bot/`.

## Files
- `fetch_lists.py` — hourly builder. Pulls `snapshot-ru-clean.json`, applies
  curation (forbidden slugs/categories, overrides, overlays, admin domains),
  subtracts Yandex (anti-detect), and writes:
  - `allowed_ips.json` / `allowed_ips_v6.json` — flat (legacy)
  - `allowed_ips_by_category.json` — per-category (preset selection)
  - `allowed_ips_priority.json` — hard-pinned top services (v4+v6)
  - `allowed_ips_ordered.json` — **per-service popularity-ranked**, each
    service's v4 CIDRs immediately followed by its v6 (v4+v6 adjacent),
    deduped, Yandex-subtracted. This is the primary AllowedIPs source.
- `bot.baton.py` / `bot.kvn.py` — bot.py per server (different WG container
  layout). `generate_client_config()` builds AllowedIPs as:
  `DNS + priority_head + ordered` (dedup, order preserved).

## Popularity ranking
Static (`SERVICE_POPULARITY` + `CATEGORY_POPULARITY` in fetch_lists.py).
Telegram > YouTube > WhatsApp > Instagram > ChatGPT > Google > Discord >
Gemini/Claude > … > porn(tail). Future: dynamic from unbound query-log.

## Firewall (not in repo, on servers)
- TCP MSS clamp 1340/1320 (Instagram fragmentation)
- Anti-QUIC REJECT Google UDP/443 v4+v6 (YouTube fast TCP-fallback)
- fw-watchdog.sh (cron */3) restores rules after docker-restart flush
- rus (85.204.240.39): UDP-relay DNAT 43835 → baton (RF-hop)
