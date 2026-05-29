# Shadowrocket configs (sr/)

Конфиги для Shadowrocket (iOS/iPadOS/macOS/tvOS) из того же каталога, что и AmneziaWG —
`iplist-mirror`, RU-вычтенный снапшот `snapshot-ru-clean.json`. Формат «ip-list proxy»:
самодостаточный конфиг, по каждому сервису сначала `DOMAIN-SUFFIX → PROXY`, затем точный
`IP-CIDR → PROXY`. Максимально точные адреса — и домены, и IP. В отличие от AWG (где список
урезан под лимит памяти iOS-туннеля), в SR лимита нет — кладём полный набор.

## Архитектура

- **Прокси (сервер)** — твоя VLESS-подписка (vless://... через rus-relay). Добавляется в SR
  отдельно, выбирается в Home. В `.conf` сервера НЕТ — конфиг ссылается на политику `PROXY`
  = текущий выбранный сервер. Поэтому один и тот же `.conf` работает для **любого сервера**
  (baton, kvn, ...) — меняется только подписка.
- **Маршруты** — зашиты в `split.conf` по сервисам (домены + IP), авто-обновление по `update-url`.

## Файлы

| Файл | Что делает |
|------|-----------|
| `split.conf` | Раздельное: по каждому сервису DOMAIN-SUFFIX + точный IP-CIDR → PROXY, остальное (`FINAL`) напрямую. Самодостаточный (~29k доменов + ~9.4k CIDR, 190 сервисов) |
| `clean.conf` | Полный туннель кроме РФ: всё через прокси, российские адреса напрямую (банки/госуслуги, звонки) |
| `blocked-services.list` | Плоский IP-CIDR набор (для варианта через `RULE-SET`, если нужен lightweight-конфиг) |
| `build_sr.py` | Генератор `split.conf` + `.list` из `snapshot-ru-clean.json` (репо) |

## Добавить в один клик (iPhone)

Открыть на устройстве с установленным Shadowrocket:

- **Split:** `shadowrocket://install-config?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaklaki52%2Fiplist-mirror%2Fmain%2Fsr%2Fsplit.conf`
- **Clean:** `shadowrocket://install-config?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaklaki52%2Fiplist-mirror%2Fmain%2Fsr%2Fclean.conf`

Или вручную: Config → "+" → Download from URL → вставить raw-ссылку.

## Обновление

```bash
python3 sr/build_sr.py
git add sr/split.conf sr/blocked-services.list && git commit -m "chore(sr): refresh" && git push
```

SR подтянет обновлённый `split.conf` автоматически (по `update-url`).
Лучше — завести этот шаг в дневной билд репо, тогда конфиг обновляется вместе со снапшотом.
