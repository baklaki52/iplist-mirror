# Shadowrocket configs (sr/)

Модульные конфиги для Shadowrocket (iOS/iPadOS/macOS/tvOS). Адреса берутся из того же
источника, что и AmneziaWG — `iplist-mirror`, RU-вычтенный плоский список
`all-cidrs-ru-clean.json`. В отличие от AWG (где список урезан под лимит памяти
iOS-туннеля), в SR через `RULE-SET` лимита нет — кладём ПОЛНЫЙ набор (4411 CIDR).

## Архитектура (почему это «модульно» и «в один клик»)

Три независимых слоя:

1. **Прокси (сервер)** — твоя VLESS-подписка (vless://... через rus-relay).
   Добавляется в SR отдельно, выбирается в Home. В `.conf` сервера НЕТ —
   конфиг ссылается на политику `PROXY` = текущий выбранный сервер.
2. **Маршруты** — `blocked-services.list` (полный RU-вычтенный набор всех
   заблокированных сервисов), подключается по ссылке через `RULE-SET`. Не зашит в конфиг.
3. **Конфиг** — `.conf` с `[General]` + `[Rule]`. Добавляется по URL,
   авто-обновляется через `update-url`.

Поэтому одни и те же `.conf` работают для **любого сервера** (baton, kvn, ...) —
меняется только подписка. Ничего не хардкодится.

## Файлы

| Файл | Что делает |
|------|-----------|
| `split.conf` | Раздельное туннелирование: через прокси только заблокированные сервисы, остальное напрямую через оператора |
| `clean.conf` | Полный туннель кроме РФ: всё через прокси, российские адреса напрямую (банки/госуслуги, звонки) |
| `blocked-services.list` | IP-CIDR/IP-CIDR6, полный RU-вычтенный набор (4411 CIDR), генерится из `all-cidrs-ru-clean.json` |
| `build_sr.py` | Генератор `.list` из `all-cidrs-ru-clean.json` (репо), не с сервера |

## Добавить в один клик (iPhone)

Открыть на устройстве с установленным Shadowrocket:

- **Split:** `shadowrocket://install-config?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaklaki52%2Fiplist-mirror%2Fmain%2Fsr%2Fsplit.conf`
- **Clean:** `shadowrocket://install-config?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaklaki52%2Fiplist-mirror%2Fmain%2Fsr%2Fclean.conf`

Или вручную: Config → "+" → Download from URL → вставить raw-ссылку.

## Обновление списка

```bash
# из корня репо, источник — RU-вычтенный снапшот в самом репо
python3 sr/build_sr.py
git add sr/blocked-services.list && git commit -m "chore(sr): refresh blocked-services.list" && git push
```

SR подтянет обновлённый список автоматически (RULE-SET кэшируется и обновляется по update-url).
Лучше — завести этот шаг в дневной билд репо, тогда `.list` обновляется вместе со снапшотом.
