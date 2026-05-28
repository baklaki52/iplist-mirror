# Shadowrocket configs (sr/)

Модульные конфиги для Shadowrocket (iOS/iPadOS/macOS/tvOS), построенные на том же
наборе CIDR, что и AmneziaWG. Маршрутизация SR совпадает с AWG, потому что оба
берут адреса из одного источника — `iplist-mirror` snapshot.

## Архитектура (почему это «модульно» и «в один клик»)

Три независимых слоя:

1. **Прокси (сервер)** — твоя VLESS-подписка (vless://... через rus-relay).
   Добавляется в SR отдельно, выбирается в Home. В `.conf` сервера НЕТ —
   конфиг ссылается на политику `PROXY` = текущий выбранный сервер.
2. **Маршруты** — `blocked-services.list` (IP-CIDR, идентичен AWG AllowedIPs),
   подключается по ссылке через `RULE-SET`. Не зашит в конфиг.
3. **Конфиг** — `.conf` с `[General]` + `[Rule]`. Добавляется по URL,
   авто-обновляется через `update-url`.

Поэтому одни и те же `.conf` работают для **любого сервера** (baton, kvn, ...) —
меняется только подписка. Ничего не хардкодится.

## Файлы

| Файл | Что делает |
|------|-----------|
| `split.conf` | Раздельное туннелирование: через прокси только заблокированные сервисы, остальное напрямую через оператора |
| `clean.conf` | Полный туннель кроме РФ: всё через прокси, российские адреса напрямую (банки/госуслуги, звонки) |
| `blocked-services.list` | IP-CIDR/IP-CIDR6, тот же набор что AWG AllowedIPs (генерится из `allowed_ips_ordered.json`) |
| `build_sr.py` | Генератор `.list` из `allowed_ips_ordered.json` |

## Добавить в один клик (iPhone)

Открыть на устройстве с установленным Shadowrocket:

- **Split:** `shadowrocket://install-config?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaklaki52%2Fiplist-mirror%2Fmain%2Fsr%2Fsplit.conf`
- **Clean:** `shadowrocket://install-config?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaklaki52%2Fiplist-mirror%2Fmain%2Fsr%2Fclean.conf`

Или вручную: Config → "+" → Download from URL → вставить raw-ссылку.

## Обновление списка

```bash
python3 build_sr.py /root/awg-bot/allowed_ips_ordered.json blocked-services.list
git add sr/blocked-services.list && git commit -m "chore(sr): refresh blocked-services.list" && git push
```

SR подтянет обновлённый список автоматически (RULE-SET кэшируется и обновляется по update-url).
