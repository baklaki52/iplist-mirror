#!/usr/bin/env python3
import hmac
import io
import json
import invites
import os
import secrets
import subprocess
import logging
import time
from pathlib import Path
from datetime import datetime

# HAPP subscription — xray client management
import xray_manager as xm
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ConversationHandler, ContextTypes, filters,
)

# --- Load .env ---
ENV_FILE = Path("/root/awg-bot/.env")
if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/root/awg-bot/bot.log"),
    ],
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_IDS = {211890697, 158102891, 156423025, 144612128, 58436594, 204394667, 483100414, 163536371}  # 163536371 = @Stasoncher

# Internal unbound DNS (docker container amnezia-dns on amnezia-dns-net bridge).
# Used both as the resolver for clients (DNS = ...) AND as a route in AllowedIPs
# so WG clients know to tunnel DNS queries. These two MUST stay in sync — one const.
DNS_IP = "172.29.172.254"
CLIENTS_VIEW_IDS = {158102891, 211890697}  # /clients access
SUPPORT_IDS = {211890697, 158102891}
MAX_CONNECTIONS = 3
CONTAINER = "amnezia-awg2"
CONFIG_PATH = "/opt/amnezia/awg/awg0.conf"
SUBNET = "10.8.1"
SERVER_IP = "5.252.20.164"
SERVER_PORT = "43835"

# Optional RU-side UDP relay endpoint — see /etc/iptables/rules.v4 on rus (85.204.240.39)
# Clients with this endpoint hit rus:43835, which DNAT-forwards to baton:43835.
RUS_HOP_ENDPOINT = "85.204.240.39:43835"
BASE_DIR = Path("/root/awg-bot")
CLIENTS_FILE = BASE_DIR / "clients.json"
IP_LIST_FILE = BASE_DIR / "allowed_ips.json"  # was "ip-list.json" (legacy);
# fetch_lists.py writes allowed_ips.json, so point bot.py at the refreshed
# file — otherwise admin_domains never make it into generated configs.
IP_LIST_V6_FILE = BASE_DIR / "allowed_ips_v6.json"
IP_LIST_YT_FILE = BASE_DIR / "allowed_ips_youtube.json"
WEB_USERS_FILE = BASE_DIR / "web_users.json"
SEEN_USERS_FILE = BASE_DIR / "seen_users.json"
USERS_META_FILE = BASE_DIR / "users_meta.json"  # tg_id -> {username,first_name,last_name,last_seen,xray_sub?}

# HAPP subscription — VLESS+Reality via amnezia-xray on 443/tcp
VLESS_SERVER_PORT = 443
XRAY_INBOUND_TAG = "vless-main"
XRAY_PUBLIC_KEY = "fW7iPgBv88YpA-YdixzGOIfMW2-8fVx-E3ly__9vhwg"
XRAY_SHORT_ID = "90b2ee98c3c82f53"
XRAY_SNI = "www.googletagmanager.com"

WAITING_NAME = 0
WAITING_MESSAGE = 1
WAITING_REPLY = 2
WAITING_BROADCAST = 3
WAITING_ADMIN_DOMAIN = 4  # Stage 3: /admin_domains add flow
WAITING_MY_DOMAIN = 5     # PR 1: /my_domains add flow (per-user)

ADMIN_DOMAINS_FILE = BASE_DIR / "admin_domains.json"
USER_DOMAINS_FILE = BASE_DIR / "user_domains.json"
# Rich format: {tg_id_str: [{domain, ips_v4, ips_v6, resolved_at}, ...]}
# Migrated 2026-04-25 from flat {tg_id_str: [str, ...]} to match kvn awg-bot.
import user_domains as ud
from tg_html import install_bridge
POPULAR_DOMAINS_FILE = BASE_DIR / "popular_domains.json"  # {domain: {users:[],alerted,skipped,promoted}}
POPULAR_THRESHOLD = 3
MAX_DOMAINS_PER_USER = 10

AWG_PARAMS = {
    "Jc": "4", "Jmin": "10", "Jmax": "50",
    "S1": "29", "S2": "65", "S3": "32", "S4": "15",
    "H1": "1926573420-2002091202",
    "H2": "2136546621-2143265291",
    "H3": "2145026947-2146302425",
    "H4": "2146541571-2147211548",
}


# --- Data helpers ---


def _esc_md(s):
    """Escape Markdown special chars in user-supplied text."""
    if not s: return ""
    for ch in ("\\", "`", "*", "_", "[", "]", "(", ")", "~", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
        s = s.replace(ch, "\\" + ch)
    return s

def load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    os.chmod(path, 0o600)


def load_clients() -> dict:
    return load_json(CLIENTS_FILE)


def save_clients(clients: dict):
    save_json(CLIENTS_FILE, clients)


# IPV4_ONLY: скрывает IPv6 из сгенерированных Amnezia-конфигов. Контекст:
# в РФ введено требование детектировать VPN на стороне сервисов, а один из
# сигналов детекции — поведение клиента с IPv6 через туннель при отсутствии
# IPv6 у его провайдера. Стриппим ::/0 и v6 CIDR из AllowedIPs — роутинг
# тогда чисто v4 и не даёт сигналов. Выключить — True → False.
IPV4_ONLY = True


def load_allowed_ips() -> str:
    if IP_LIST_FILE.exists():
        ips = json.loads(IP_LIST_FILE.read_text())
        return ", ".join(ips)
    return "0.0.0.0/0, ::/0" if not IPV4_ONLY else "0.0.0.0/0"


def load_allowed_ips_v6() -> list:
    if IP_LIST_V6_FILE.exists():
        return json.loads(IP_LIST_V6_FILE.read_text())
    return []


def load_allowed_ips_youtube() -> list:
    if IP_LIST_YT_FILE.exists():
        return json.loads(IP_LIST_YT_FILE.read_text())
    return []


def load_seen_users() -> set:
    data = load_json(SEEN_USERS_FILE)
    return set(data.get("seen", []))


def save_seen_user(user_id: int):
    seen = load_seen_users()
    seen.add(user_id)
    save_json(SEEN_USERS_FILE, {"seen": list(seen)})


def load_users_meta() -> dict:
    return load_json(USERS_META_FILE)


def save_user_meta(user) -> None:
    """Persist Telegram user info (username, name) so we can resolve later.
    Called from every command/button handler so the metadata stays fresh.
    Updates identity fields only — preserves xray_sub and any other custom keys."""
    if not user or not getattr(user, "id", None):
        return
    meta = load_users_meta()
    key = str(user.id)
    existing = meta.setdefault(key, {})
    existing.update({
        "id": user.id,
        "username": user.username or "",
        "first_name": user.first_name or "",
        "last_name": user.last_name or "",
        "last_seen": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    save_json(USERS_META_FILE, meta)
    # also keep them in seen_users for broadcast
    save_seen_user(user.id)


# ── HAPP subscription — xray_sub field in users_meta ───────────────────

def sync_xray_clients_from_meta():
    """Ensure all xray_sub UUIDs from users_meta are present in server.json.

    One-shot batch: collects wanted UUIDs, passes to xm.sync_clients which
    restarts the container at most once if any UUIDs are added. Preserves
    existing non-bot clients (pre-existing Amnezia accounts).
    """
    meta = load_users_meta()
    wanted = []
    for uid, user_meta in meta.items():
        sub = (user_meta or {}).get("xray_sub") or {}
        u = sub.get("uuid")
        if u:
            wanted.append(u)
    if not wanted:
        logger.info("xray_sync: no xray_sub uuids in users_meta, nothing to do")
        return
    try:
        added = xm.sync_clients(wanted, inbound_tag=XRAY_INBOUND_TAG)
        logger.info(f"xray_sync: wanted={len(wanted)} added_now={added}")
    except xm.XrayError as e:
        logger.warning(f"xray_sync: failed: {e!r}")


def create_xray_sub(user):
    """Generate UUID + 64-hex secret, register UUID in xray, persist to users_meta.

    Idempotent: if user already has xray_sub, returns existing (uuid, secret).
    """
    import uuid as _uuid_mod
    meta = load_users_meta()
    uid_str = str(user.id)
    user_meta = meta.setdefault(uid_str, {
        "id": user.id,
        "username": getattr(user, "username", "") or "",
        "first_name": getattr(user, "first_name", "") or "",
        "last_name": getattr(user, "last_name", "") or "",
    })
    sub = user_meta.get("xray_sub")
    if sub and sub.get("uuid") and sub.get("secret"):
        return sub["uuid"], sub["secret"]

    client_uuid = str(_uuid_mod.uuid4())
    secret_str = secrets.token_hex(32)

    xm.add_client(client_uuid, inbound_tag=XRAY_INBOUND_TAG)

    user_meta["xray_sub"] = {
        "uuid": client_uuid,
        "secret": secret_str,
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    save_json(USERS_META_FILE, meta)
    return client_uuid, secret_str


def rotate_xray_sub(user) -> str:
    """Generate new 64-hex secret, keep UUID. Returns new secret.

    Invalidates cached crypt5 deep-link — new secret means new sub-URL.
    """
    meta = load_users_meta()
    uid_str = str(user.id)
    user_meta = meta.get(uid_str, {})
    sub = user_meta.get("xray_sub")
    if not sub:
        _, new_secret = create_xray_sub(user)
        return new_secret
    new_secret = secrets.token_hex(32)
    sub["secret"] = new_secret
    sub["rotated_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    # Drop cached crypt5 — recomputed on next /install/<secret> access
    sub.pop("crypt5", None)
    save_json(USERS_META_FILE, meta)
    return new_secret


def get_or_build_crypt5(user_id, sub_url: str) -> str:
    """Return cached happ://crypt5/... link for user, or fetch-and-cache it."""
    import subscription as _sub
    meta = load_users_meta()
    uid_str = str(user_id)
    user_meta = meta.get(uid_str, {})
    sub = user_meta.get("xray_sub") or {}
    cached = sub.get("crypt5")
    if cached and isinstance(cached, str) and cached.startswith("happ://"):
        return cached
    crypt5 = _sub.encrypt_happ_link(sub_url)
    if sub:
        sub["crypt5"] = crypt5
        save_json(USERS_META_FILE, meta)
    return crypt5


def get_xray_sub_by_secret(secret):
    """Constant-time lookup by secret. Returns (uid_str, uuid) or None."""
    if not isinstance(secret, str) or len(secret) != 64:
        return None
    try:
        int(secret, 16)
    except ValueError:
        return None

    meta = load_users_meta()
    for uid_str, user_meta in meta.items():
        sub = (user_meta or {}).get("xray_sub") or {}
        stored = sub.get("secret")
        if not stored:
            continue
        if hmac.compare_digest(secret, stored):
            return uid_str, sub.get("uuid")
    return None


def revoke_xray_sub(user) -> bool:
    """Remove xray client + clear users_meta.xray_sub. Idempotent."""
    meta = load_users_meta()
    uid_str = str(user.id)
    user_meta = meta.get(uid_str, {})
    sub = user_meta.get("xray_sub")
    if not sub:
        return False
    try:
        xm.remove_client(sub["uuid"], inbound_tag=XRAY_INBOUND_TAG)
    except xm.XrayError as e:
        logger.warning(f"revoke_xray_sub: xray api failure (continuing): {e!r}")
    user_meta.pop("xray_sub", None)
    save_json(USERS_META_FILE, meta)
    return True


def format_user_label(user_id) -> str:
    """Return a human label '@username (Имя)' or 'id:N' if unknown."""
    if user_id is None:
        return "?"
    try:
        uid_str = str(int(user_id))
    except (TypeError, ValueError):
        return str(user_id)
    meta = load_users_meta().get(uid_str)
    if not meta:
        return f"id:{uid_str}"
    parts = []
    if meta.get("username"):
        parts.append(f"@{meta['username']}")
    name = " ".join(p for p in [meta.get("first_name", ""), meta.get("last_name", "")] if p).strip()
    if name:
        parts.append(name)
    parts.append(f"id:{uid_str}")
    return " ".join(parts) if parts else f"id:{uid_str}"


# --- Docker exec (safe) ---

def docker_exec(cmd: str, input_data: str = None) -> str:
    args = ["docker", "exec"]
    if input_data is not None:
        args.append("-i")
    args.extend([CONTAINER, "bash", "-c", cmd])
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=30,
        input=input_data,
    )
    return result.stdout.strip()


def get_server_pubkey() -> str:
    return docker_exec("awg show awg0 public-key")


def gen_keypair() -> tuple:
    privkey = docker_exec("awg genkey")
    pubkey = docker_exec("awg pubkey", input_data=privkey)
    return privkey, pubkey


def get_psk() -> str:
    return docker_exec("awg genpsk")


def get_used_ips() -> set:
    clients = load_clients()
    ips = {c["ip"] for c in clients.values()}
    conf = docker_exec(f"cat {CONFIG_PATH}")
    for line in conf.splitlines():
        line = line.strip()
        if line.startswith("AllowedIPs"):
            ip = line.split("=")[1].strip().split("/")[0].strip()
            ips.add(ip)
    ips.add(f"{SUBNET}.0")
    return ips


def next_ip() -> str:
    used = get_used_ips()
    for i in range(1, 255):
        ip = f"{SUBNET}.{i}"
        if ip not in used:
            return ip
    raise RuntimeError("No free IPs")


def add_peer_to_awg(pubkey: str, psk: str, client_ip: str):
    docker_exec(
        f"cat > /tmp/psk.tmp && "
        f"awg set awg0 peer '{pubkey}' "
        f"allowed-ips {client_ip}/32 "
        f"preshared-key /tmp/psk.tmp && "
        f"rm -f /tmp/psk.tmp",
        input_data=psk,
    )
    peer_block = (
        f"\n[Peer]\n"
        f"PublicKey = {pubkey}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_ip}/32\n"
    )
    docker_exec("cat >> " + CONFIG_PATH, input_data=peer_block)


def remove_peer_from_awg(pubkey: str):
    docker_exec(f"awg set awg0 peer '{pubkey}' remove")
    conf = docker_exec(f"cat {CONFIG_PATH}")
    new_lines, skip = [], False
    for line in conf.splitlines():
        if line.strip().startswith("[Peer]"):
            skip = False
            new_lines.append(line)
            continue
        if line.strip().startswith("PublicKey") and pubkey in line:
            new_lines.pop()
            skip = True
            continue
        if skip:
            if line.strip().startswith("["):
                skip = False
                new_lines.append(line)
            continue
        new_lines.append(line)
    new_conf = "\n".join(new_lines).strip() + "\n"
    docker_exec(f"cat > {CONFIG_PATH}", input_data=new_conf)


def _load_user_domain_ips_for(user_id) -> tuple:
    """Return (v4_list, v6_list) of CIDR strings for a given tg_id (or 'w_*').
    Reads pre-resolved IPs from rich-format user_domains.json via ud.collect_ips
    and appends /32 (v4) or /128 (v6) masks for AllowedIPs compatibility.
    Without masks, iOS Network Extension rejects the config with Error 101.
    Only int tg_ids have entries; web-only owners get empty lists."""
    if not isinstance(user_id, int):
        return [], []
    v4_raw, v6_raw = ud.collect_ips(USER_DOMAINS_FILE, str(user_id))
    v4 = [ip if "/" in ip else f"{ip}/32" for ip in v4_raw]
    v6 = [ip if "/" in ip else f"{ip}/128" for ip in v6_raw]
    return v4, v6


ALLOWED_IPS_BY_CAT_FILE = BASE_DIR / "allowed_ips_by_category.json"

# PR 2: per-preset category lists. None / "standard" = use flat allowed_ips.json
# (legacy behavior). Other presets filter allowed_ips_by_category.json.
PRESET_CATEGORIES = {
    "social":    ["socials", "messengers", "discord", "youtube", "video", "work", "jetbrains"],
    "social-ai": ["socials", "messengers", "discord", "youtube", "video", "work", "jetbrains", "ai"],
}

# UI label for each preset — used in peer detail views.
PRESET_LABELS = {
    None:        "Amnezia (всё)",
    "standard":  "Amnezia (всё)",
    "social":    "Общение + видео",
    "social-ai": "Общение + нейросети",
    "custom":    "свой набор",
}

# Human-facing category metadata for the custom constructor UI.
CATEGORY_META = {
    "ai":         ("🤖", "нейросети"),
    "anime":      ("🌸", "аниме"),
    "art":        ("🎨", "арт"),
    "discord":    ("🎧", "Discord"),
    "education":  ("🎓", "образование"),
    "games":      ("🎮", "игры"),
    "jetbrains":  ("🧰", "JetBrains"),
    "messengers": ("📨", "мессенджеры"),
    "music":      ("🎵", "музыка"),
    "news":       ("📰", "новости"),
    "porn":       ("🔞", "18+"),
    "search":     ("🔍", "поиск"),
    "shop":       ("🛍", "магазины"),
    "socials":    ("👥", "соцсети"),
    "tools":      ("🛠", "инструменты"),
    "torrent":    ("🧲", "торренты"),
    "video":      ("🎞", "видео"),
    "work":       ("💼", "работа"),
    "youtube":    ("🎬", "YouTube"),
}


def _category_pretty_list(cats) -> str:
    """Comma-join category slugs → humanised names for descriptions."""
    return ", ".join(CATEGORY_META.get(c, (None, c))[1] for c in cats)


def _build_ips_for_categories(cats):
    """Union v4/v6 CIDR sets for the given categories. Always includes the
    _admin_domains bucket so global additions keep working regardless of
    which categories are picked. Returns (v4_csv, v6_csv) or None if the
    category-split file isn't available yet."""
    if not cats:
        return None
    if not ALLOWED_IPS_BY_CAT_FILE.exists():
        return None
    try:
        data = json.loads(ALLOWED_IPS_BY_CAT_FILE.read_text())
    except Exception:
        return None
    v4_set, v6_set = set(), set()
    for cat in cats:
        v4_set.update(data.get("v4", {}).get(cat, []))
        v6_set.update(data.get("v6", {}).get(cat, []))
    v4_set.update(data.get("v4", {}).get("_admin_domains", []))
    v6_set.update(data.get("v6", {}).get("_admin_domains", []))
    return ", ".join(sorted(v4_set)), ", ".join(sorted(v6_set))


def _build_ips_for_preset(preset, custom_categories=None):
    """None / standard / all → flat list (fallback); named preset or 'custom'
    → categorised list."""
    if not preset or preset == "standard" or preset == "all":
        return None
    if preset == "custom":
        return _build_ips_for_categories(custom_categories or [])
    cats = PRESET_CATEGORIES.get(preset)
    if not cats:
        return None
    return _build_ips_for_categories(cats)


def _load_categories_with_counts():
    """Sorted list of (cat, v4_count, v6_count) excluding private buckets."""
    if not ALLOWED_IPS_BY_CAT_FILE.exists():
        return []
    try:
        data = json.loads(ALLOWED_IPS_BY_CAT_FILE.read_text())
    except Exception:
        return []
    out = []
    all_cats = sorted(set(data.get("v4", {}).keys()) | set(data.get("v6", {}).keys()))
    for cat in all_cats:
        if cat.startswith("_"):
            continue
        out.append((cat, len(data.get("v4", {}).get(cat, [])),
                        len(data.get("v6", {}).get(cat, []))))
    return out


def _render_custom_keyboard(selected_set):
    """Build the category-toggle inline keyboard. 2 cols × N rows, plus
    [ℹ️ что внутри?] / [Create] / [Back] footer."""
    cats = _load_categories_with_counts()
    buttons = []
    row = []
    for cat, n4, _n6 in cats:
        emoji, name = CATEGORY_META.get(cat, ("·", cat))
        mark = "✅" if cat in selected_set else "⬜️"
        label = f"{mark} {emoji} {name} ({n4})"
        row.append(InlineKeyboardButton(label, callback_data=f"custom_toggle:{cat}"))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    buttons.append([InlineKeyboardButton("ℹ️ Что в каждой категории?", callback_data="custom_info")])
    buttons.append([InlineKeyboardButton("🌐 Добавить свой домен", callback_data="mydom_add:custom")])
    buttons.append([
        InlineKeyboardButton(f"✅ Создать ({len(selected_set)} выбрано)", callback_data="custom_done"),
        InlineKeyboardButton("⬅️ Назад", callback_data="new_pro"),
    ])
    return InlineKeyboardMarkup(buttons)


SERVICES_BY_CAT_FILE = BASE_DIR / "services_by_category.json"


def _load_services_by_category() -> dict:
    if not SERVICES_BY_CAT_FILE.exists():
        return {}
    try:
        d = json.loads(SERVICES_BY_CAT_FILE.read_text())
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _render_info_categories_keyboard():
    """Category list for drill-down into services. 2 cols + back."""
    svc_map = _load_services_by_category()
    cats = _load_categories_with_counts()
    buttons = []
    row = []
    for cat, _n4, _n6 in cats:
        emoji, name = CATEGORY_META.get(cat, ("·", cat))
        count = len(svc_map.get(cat, []))
        row.append(InlineKeyboardButton(
            f"{emoji} {name} ({count})",
            callback_data=f"custom_info_cat:{cat}",
        ))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    buttons.append([InlineKeyboardButton("⬅️ К выбору", callback_data="custom_info_back")])
    return InlineKeyboardMarkup(buttons)


def _load_ordered_ips():
    """Load allowed_ips_ordered.json — single per-service popularity-ranked
    array (v4+v6 of each service adjacent). Empty list if missing."""
    try:
        with open(BASE_DIR / "allowed_ips_ordered.json") as f:
            d = json.load(f)
            return d if isinstance(d, list) else []
    except (FileNotFoundError, json.JSONDecodeError, NameError):
        try:
            import os
            p = os.path.join(os.path.dirname(__file__), "allowed_ips_ordered.json")
            with open(p) as f:
                d = json.load(f)
                return d if isinstance(d, list) else []
        except Exception:
            return []


def _load_priority_ips():
    """Load allowed_ips_priority.json → {"v4":[...], "v6":[...]}.
    Critical services pinned to the front of AllowedIPs. Empty if file missing."""
    try:
        with open(BASE_DIR / "allowed_ips_priority.json") as f:
            d = json.load(f)
            return {"v4": d.get("v4", []), "v6": d.get("v6", [])}
    except (FileNotFoundError, json.JSONDecodeError, NameError):
        try:
            import os
            p = os.path.join(os.path.dirname(__file__), "allowed_ips_priority.json")
            with open(p) as f:
                d = json.load(f)
                return {"v4": d.get("v4", []), "v6": d.get("v6", [])}
        except Exception:
            return {"v4": [], "v6": []}


def generate_client_config(privkey, ip, psk, mode: str = "split", user_id=None,
                           preset=None, custom_categories=None,
                           endpoint_override=None) -> str:
    """Generate AmneziaWG client config.

    mode="split"   — default split tunneling.
    mode="full"    — route all traffic through the VPN (0.0.0.0/0, ::/0).
    mode="youtube" — only Google/YouTube CIDRs (legacy, not offered to new peers).

    preset — optional filter for mode="split": named preset from
    PRESET_CATEGORIES (e.g. 'social', 'social-ai'), 'custom' (requires
    custom_categories list), or None / 'standard' / 'all' = flat list.

    custom_categories — list of category slugs used when preset=='custom'.

    user_id — peer owner's Telegram id. When set, per-user domains from
    user_domain_ips.json[str(user_id)] are appended (ignored in full mode).
    """
    server_pubkey = get_server_pubkey()
    if mode == "full":
        allowed_ips = "0.0.0.0/0, ::/0"
    elif mode == "youtube":
        yt = load_allowed_ips_youtube()
        allowed_ips = ", ".join([f"{DNS_IP}/32"] + yt)
    else:
        # PR 2: preset-filtered list takes priority over the flat fallback.
        preset_ips = _build_ips_for_preset(preset, custom_categories)
        if preset_ips is not None:
            v4_csv, v6_csv = preset_ips
            allowed_ips = v4_csv + (", " + v6_csv if v6_csv else "")
        else:
            _ord = _load_ordered_ips()
            if _ord:
                # per-service popularity-ranked list (v4+v6 adjacent)
                allowed_ips = ", ".join(_ord)
            else:
                v6 = load_allowed_ips_v6()
                v6_part = (", " + ", ".join(v6)) if v6 else ", 2000::/3"
                allowed_ips = load_allowed_ips() + v6_part
        # Prepend internal DNS route + PRIORITY HEAD (critical services pinned
        # to the front so they survive iOS NE memory pressure / app timing).
        # Order: DNS, priority-v4, priority-v6, then the rest. Dedup preserves
        # order — a CIDR already in the priority head won't repeat in the tail.
        _pri = _load_priority_ips()
        _head = [f"{DNS_IP}/32"] + _pri["v4"] + _pri["v6"]
        _seen, _ordered = set(), []
        for _c in _head + [x.strip() for x in allowed_ips.split(",")]:
            _c = _c.strip()
            if _c and _c not in _seen:
                _seen.add(_c); _ordered.append(_c)
        allowed_ips = ", ".join(_ordered)

    # PR 1: per-user domain CIDRs. Union'd by appending — WG clients dedupe
    # overlapping prefixes on their side, and extras are /32-/128 anyway.
    if mode != "full":
        user_v4, user_v6 = _load_user_domain_ips_for(user_id)
        extras = user_v4 + user_v6
        if extras:
            allowed_ips = allowed_ips + ", " + ", ".join(extras)
    params = "\n".join(f"{k} = {v}" for k, v in AWG_PARAMS.items())
    return (
        f"[Interface]\n"
        f"PrivateKey = {privkey}\n"
        f"Address = {ip}/32\n"
        f"DNS = {DNS_IP}\n"
        f"{params}\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {allowed_ips}\n"
        f"Endpoint = {endpoint_override or f'{SERVER_IP}:{SERVER_PORT}'}\n"
        f"PersistentKeepalive = 25\n"
    )


def find_conn_owner(name: str, clients: dict = None) -> int | str | None:
    if clients is None:
        clients = load_clients()
    info = clients.get(name)
    return info.get("owner") if info else None


# --- Helpers ---

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def get_user_clients(user_id: int) -> dict:
    clients = load_clients()
    if is_admin(user_id):
        return clients
    return {name: info for name, info in clients.items() if info.get("owner") == user_id}


def build_caption(name: str, ip: str) -> str:
    return (
        f"*{name}*  \u2014  `{ip}`\n"
        "\n"
        "\U0001F4F2 *Какое приложение скачать?*\n"
        "\U0001F4F1 Android \u2014 [AmneziaVPN (Google Play)](https://play.google.com/store/apps/details?id=org.amnezia.vpn)\n"
        "\U0001F34F iPhone (иностр. App Store) \u2014 [AmneziaVPN](https://apps.apple.com/app/amneziavpn/id1600529900)\n"
        "\U0001F34F iPhone (рос. App Store) \u2014 [AmneziaWG](https://apps.apple.com/ru/app/amneziawg/id6478942365)\n"
        "\n"
        "\U0001F4CB *Как подключиться*\n"
        "1. Нажмите *Поделиться* на этом файле\n"
        "2. Telegram предложит переслать \u2014 нажмите *Поделиться* ещё раз\n"
        "3. Выберите приложение Amnezia\n"
        "4. Если запросит разрешения \u2014 разрешите все\n"
        "\n"
        "\u2757 *Важно*\n"
        "Сервис можно не выключать. Работает раздельное "
        "туннелирование: российские сервисы открываются "
        "напрямую под вашим IP, заблокированные \u2014 через "
        "прокси. На батарею почти не влияет."
    )


def human_bytes(b: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def main_menu_keyboard(user_id: int):
    admin = is_admin(user_id)
    if admin:
        # For admins: count their OWN connections separately, not all clients
        all_clients = load_clients()
        own_count = sum(1 for c in all_clients.values() if c.get("owner") == user_id)
        total_count = len(all_clients)
    else:
        own_count = len(get_user_clients(user_id))
        total_count = own_count

    buttons = []
    if admin or own_count < MAX_CONNECTIONS:
        label = "\U0001F195 Новое подключение" if admin else f"\U0001F195 Новое подключение ({own_count}/{MAX_CONNECTIONS})"
        buttons.append([InlineKeyboardButton(label, callback_data="new_client")])

    if admin:
        # Admins get both "my" and "all"
        buttons.append([InlineKeyboardButton(f"\U0001F4CB Мои подключения ({own_count})", callback_data="my_clients")])
        if total_count > 0:
            buttons.append([InlineKeyboardButton(f"\U0001F4CB Все подключения ({total_count})", callback_data="all_clients")])
        buttons.append([InlineKeyboardButton("\U0001F310 Мои домены", callback_data="mydom_menu")])
        buttons.append([InlineKeyboardButton("\U0001F30D Общий список доменов", callback_data="admindom_menu")])
        buttons.append([InlineKeyboardButton("\U0001F4CA Статус сервера", callback_data="server_status")])
        buttons.append([InlineKeyboardButton("\U0001F4E2 Рассылка всем", callback_data="broadcast")])
        # Admins can also write to the OTHER admins via support
        buttons.append([InlineKeyboardButton("\u2709\uFE0F Написать остальным админам", callback_data="support")])
    else:
        if own_count > 0:
            buttons.append([InlineKeyboardButton(f"\U0001F4CB Мои подключения ({own_count})", callback_data="my_clients")])
        buttons.append([InlineKeyboardButton("\U0001F310 Мои домены", callback_data="mydom_menu")])
        buttons.append([InlineKeyboardButton("\u2709\uFE0F Написать админу", callback_data="support")])    # Invite button
    used, remaining = invites.get_quota(user_id)
    if remaining == -1:
        invite_label = f"🎟 Пригласить друга (∞)"
    else:
        invite_label = f"🎟 Пригласить друга ({remaining}/{used + remaining})"
    buttons.append([InlineKeyboardButton(invite_label, callback_data="invite_create")])
    if is_admin(user_id):
        buttons.append([InlineKeyboardButton("🔓 Открытая ссылка (admin)", callback_data="invite_open")])
        if invites.list_open_tokens(user_id):
            buttons.append([InlineKeyboardButton("🗂 Мои открытые ссылки", callback_data="invite_open_list")])
    if user_id in CLIENTS_VIEW_IDS:
        buttons.append([InlineKeyboardButton("👥 Клиенты бота", callback_data="clients_view")])

    return InlineKeyboardMarkup(buttons)


# --- Handlers ---

async def post_init(app: Application):
    # Bootstrap invites allowlist from clients.json owners
    try:
        import json
        clients = json.loads(CLIENTS_FILE.read_text()) if CLIENTS_FILE.exists() else {}
        owners = {rec.get("owner") for rec in clients.values() if rec.get("owner")}
        invites.bootstrap_from(list(owners), admin_ids=list(ADMIN_IDS))
        for _aid in ADMIN_IDS:
            invites.ensure_allowed(_aid, mark_admin=True)
    except Exception as _e:
        logger.warning(f"invites bootstrap failed: {_e}")
    await app.bot.set_my_commands([
        BotCommand("start", "Главное меню"),
        BotCommand("new", "Новое подключение"),
        BotCommand("my", "Мои подключения"),
        BotCommand("my_domains", "Мои домены"),
        BotCommand("invite", "Пригласить друга"),
        BotCommand("support", "Написать админу"),
        BotCommand("verify", "Верификация веб-аккаунта"),
    ])
    # Admin-scoped menu (shown only in CLIENTS_VIEW_IDS chats)
    try:
        from telegram import BotCommandScopeChat
        admin_cmds = [
            BotCommand("start", "Главное меню"),
            BotCommand("new", "Новое подключение"),
            BotCommand("my", "Мои подключения"),
            BotCommand("my_domains", "Мои домены"),
            BotCommand("invite", "Пригласить друга"),
            BotCommand("admin_domains", "Общий список доменов (админ)"),
            BotCommand("broadcast", "Рассылка (админ)"),
            BotCommand("support", "Написать админу"),
            BotCommand("verify", "Верификация веб-аккаунта"),
            BotCommand("clients", "Клиенты бота (админ)"),
        ]
        for admin_id in CLIENTS_VIEW_IDS:
            await app.bot.set_my_commands(admin_cmds, scope=BotCommandScopeChat(chat_id=admin_id))
    except Exception as e:
        logger.warning(f"scoped set_my_commands failed: {e}")



async def cmd_clients(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List bot clients with clickable TG links. Restricted to CLIENTS_VIEW_IDS."""
    user = update.effective_user
    if user.id not in CLIENTS_VIEW_IDS:
        return

    import json
    try:
        clients = json.loads(CLIENTS_FILE.read_text())
    except Exception as e:
        await update.message.reply_text(f"Не смог прочитать clients.json: {e}")
        return

    try:
        meta = json.loads(USERS_META_FILE.read_text())
    except Exception:
        meta = {}

    # Group clients by owner tg_id
    by_owner = {}
    for name, rec in clients.items():
        owner = rec.get("owner")
        if owner is None:
            continue
        by_owner.setdefault(str(owner), []).append(name)

    """baton_clients_html_v2"""
    def esc(s):
        s = str(s)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _user_link(uid, label):
        # tg://user?id=N requires NUMERIC uid. w_* is a web-only user — no link.
        if str(uid).startswith("w_"):
            return label
        return '<a href="tg://user?id={}">{}</a>'.format(uid, label)

    header = "\U0001F465 <b>Клиенты бота</b> ({} юзеров, {} конфигов)".format(
        len(by_owner), sum(len(v) for v in by_owner.values())
    )
    lines = [header, ""]
    rows = sorted(by_owner.items(), key=lambda kv: -len(kv[1]))
    for uid, conn_names in rows:
        m = meta.get(uid, {})
        uname = m.get("username", "")
        first = m.get("first_name", "")
        last = m.get("last_name", "")
        full = " ".join(p for p in [first, last] if p).strip()
        if uname:
            label = "@" + esc(uname)
            if full:
                label += " (" + esc(full) + ")"
            link = _user_link(uid, label)
        elif full:
            link = "{} <code>id:{}</code>".format(_user_link(uid, esc(full)), uid)
        else:
            link = _user_link(uid, "id:{}".format(uid))
            if str(uid).startswith("w_"):
                link = "<code>id:{}</code>".format(uid)
        conns = ", ".join(esc(n) for n in conn_names[:6])
        if len(conn_names) > 6:
            conns += " +{}".format(len(conn_names) - 6)
        lines.append("\u2022 {} \u2014 {} ({})".format(link, len(conn_names), conns))

    MAX = 4000
    chunks = []
    cur = ""
    for ln in lines:
        if len(cur) + len(ln) + 1 > MAX:
            chunks.append(cur)
            cur = ln
        else:
            cur = (cur + "\n" + ln) if cur else ln
    if cur:
        chunks.append(cur)

    for ch in chunks:
        await update.message.reply_text(ch, parse_mode="HTML", disable_web_page_preview=True)



async def cmd_invite(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate invite link (command + called from button)."""
    user = update.effective_user
    if not is_admin(user.id) and not invites.is_allowed(user.id):
        await update.message.reply_text("🔒 Нет доступа.")
        return
    token, remaining = invites.create_token(user.id)
    rem_display = "∞" if remaining == -1 else remaining
    if not token:
        used, rem = invites.get_quota(user.id)
        pending = len(invites.list_pending_tokens(user.id))
        await update.message.reply_text(
            f"🎟 Лимит приглашений исчерпан.\n\n"
            f"Использовано: {used}\nОжидают активации: {pending}\n\n"
            f"Когда кто-то активирует вашу ссылку, место освободится (если осталась квота)."
        )
        return
    bot_username = (await context.bot.get_me()).username
    url = f"https://t.me/{bot_username}?start={token}"
    await update.message.reply_text(
        f"🎟 *Ваша пригласительная ссылка*\n\n"
        f"{url}\n\n"
        f"Отправьте её другу. После того как он нажмёт «Start» — получит доступ.\n\n"
        f"Осталось инвайтов: *{"\u221e" if remaining == -1 else remaining}*",
        parse_mode="Markdown", disable_web_page_preview=True,
    )


def _invite_link_html(bot_username, token, remaining_display, *, open_uses=None, expires_days=None):
    """Render the 'here is your invite link' message (HTML parse_mode)."""
    url = f"https://t.me/{bot_username}?start={token}"
    header = "🔓 <b>Открытая ссылка</b>" if open_uses else "🎟 <b>Ваша пригласительная ссылка</b>"
    lines = [
        header,
        "",
        f'<a href="{url}">{url}</a>',
        "",
        "Перешлите сообщение другу или скопируйте ссылку. "
        "Когда он нажмёт «Start» — получит доступ к боту.",
    ]
    if open_uses:
        uses_str = "без лимита" if open_uses == "inf" else f"до {open_uses} человек"
        exp_str = "бессрочно" if not expires_days else f"{expires_days} дн."
        lines += ["", f"Лимит: <b>{uses_str}</b> · срок: <b>{exp_str}</b>"]
    else:
        lines += ["", f"Осталось инвайтов: <b>{remaining_display}</b>"]
    return "\n".join(lines)


async def cb_invite_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not is_admin(user.id) and not invites.is_allowed(user.id):
        await query.edit_message_text("🔒 Нет доступа.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]))
        return
    token, remaining = invites.create_token(user.id)
    rem_display = "∞" if remaining == -1 else remaining
    if not token:
        used, rem = invites.get_quota(user.id)
        pending = len(invites.list_pending_tokens(user.id))
        await query.edit_message_text(
            f"🎟 Лимит исчерпан.\nИспользовано: {used}, ожидают: {pending}"
        , reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]))
        return
    bot_username = (await context.bot.get_me()).username
    body = _invite_link_html(bot_username, token, rem_display)
    await query.edit_message_text(
        body, parse_mode="HTML", disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]),
    )


# ── Open (multi-use, admin-only) invite links ─────────────────────────

def _invite_open_uses_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("5", callback_data="invite_open_uses:5"),
            InlineKeyboardButton("10", callback_data="invite_open_uses:10"),
            InlineKeyboardButton("25", callback_data="invite_open_uses:25"),
            InlineKeyboardButton("∞", callback_data="invite_open_uses:inf"),
        ],
        [InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")],
    ])


def _invite_open_expiry_kb(uses):
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("1 день", callback_data=f"invite_open_make:{uses}:1"),
            InlineKeyboardButton("7 дней", callback_data=f"invite_open_make:{uses}:7"),
        ],
        [
            InlineKeyboardButton("30 дней", callback_data=f"invite_open_make:{uses}:30"),
            InlineKeyboardButton("∞", callback_data=f"invite_open_make:{uses}:inf"),
        ],
        [InlineKeyboardButton("⬅️ К выбору лимита", callback_data="invite_open")],
    ])


async def cb_invite_open(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not is_admin(user.id):
        await query.edit_message_text(
            "🔒 Открытые ссылки доступны только админам.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]),
        )
        return
    await query.edit_message_text(
        "🔓 <b>Открытая ссылка</b>\n\nСколько человек могут пройти по одной ссылке?",
        parse_mode="HTML", reply_markup=_invite_open_uses_kb(),
    )


async def cb_invite_open_uses(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    uses = query.data.split(":", 1)[1]
    label = "без лимита" if uses == "inf" else f"до {uses} человек"
    await query.edit_message_text(
        f"🔓 <b>Открытая ссылка</b>\n\nЛимит: <b>{label}</b>\n\nСрок действия ссылки?",
        parse_mode="HTML", reply_markup=_invite_open_expiry_kb(uses),
    )


async def cb_invite_open_make(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    parts = query.data.split(":")
    if len(parts) != 3:
        await query.edit_message_text("Ошибка формата кнопки.")
        return
    _, uses_s, days_s = parts
    max_uses = 10**9 if uses_s == "inf" else int(uses_s)
    expires_in_days = None if days_s == "inf" else int(days_s)

    token, _rem = invites.create_token(
        user.id, max_uses=max_uses, expires_in_days=expires_in_days,
    )
    if not token:
        await query.edit_message_text(
            "❌ Не удалось создать ссылку.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]),
        )
        return
    bot_username = (await context.bot.get_me()).username
    body = _invite_link_html(
        bot_username, token, None,
        open_uses=("inf" if uses_s == "inf" else int(uses_s)),
        expires_days=(None if days_s == "inf" else int(days_s)),
    )
    await query.edit_message_text(
        body, parse_mode="HTML", disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🗂 Мои открытые ссылки", callback_data="invite_open_list")],
            [InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")],
        ]),
    )


async def cb_invite_open_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    tokens = invites.list_open_tokens(user.id)
    if not tokens:
        await query.edit_message_text(
            "🗂 <b>Мои открытые ссылки</b>\n\nПока ни одной активной.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔓 Создать открытую", callback_data="invite_open")],
                [InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")],
            ]),
        )
        return
    now = int(time.time())
    lines = ["🗂 <b>Мои открытые ссылки</b>", ""]
    rows = []
    for tok, t in tokens:
        max_u = t.get("max_uses") or 1
        used = len(t["used_by"] if isinstance(t.get("used_by"), list) else ([] if not t.get("used_by") else [t["used_by"]]))
        exp = t.get("expires_at")
        exp_str = f"{max(0, (exp - now) // 86400)} дн." if exp else "∞"
        uses_str = "∞" if max_u >= 10**9 else str(max_u)
        rows.append([InlineKeyboardButton(
            f"🗑 {used}/{uses_str} · {exp_str} · {tok[:6]}…",
            callback_data=f"invite_open_revoke:{tok}",
        )])
        lines.append(f"• <code>{tok}</code> — {used}/{uses_str}, осталось {exp_str}")
    rows.append([InlineKeyboardButton("🔓 Создать новую", callback_data="invite_open")])
    rows.append([InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")])
    await query.edit_message_text(
        "\n".join(lines), parse_mode="HTML", disable_web_page_preview=True,
        reply_markup=InlineKeyboardMarkup(rows),
    )


async def cb_invite_open_revoke(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user = query.from_user
    if not is_admin(user.id):
        await query.answer()
        return
    tok = query.data.split(":", 1)[1]
    ok, msg = invites.revoke_token(tok, user.id)
    await query.answer(msg, show_alert=False)
    await cb_invite_open_list(update, context)


async def cb_clients_view(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if user.id not in CLIENTS_VIEW_IDS:
        await query.edit_message_text("🔒 Нет доступа.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]))
        return
    chat_id = query.message.chat_id
    # Build client list inline (same logic as cmd_clients)
    import json
    try:
        clients = json.loads(CLIENTS_FILE.read_text())
    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"Не смог прочитать clients.json: {e}")
        return
    try:
        meta = json.loads(USERS_META_FILE.read_text())
    except Exception:
        meta = {}
    by_owner = {}
    for name, rec in clients.items():
        owner = rec.get("owner")
        if owner is None:
            continue
        by_owner.setdefault(str(owner), []).append(name)
    def esc(s):
        s = str(s)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _user_link(uid, label):
        if str(uid).startswith("w_"):
            return label
        return '<a href="tg://user?id={}">{}</a>'.format(uid, label)

    header = "\U0001F465 <b>Клиенты бота</b> ({} юзеров, {} конфигов)".format(
        len(by_owner), sum(len(v) for v in by_owner.values()))
    lines = [header, ""]
    rows = sorted(by_owner.items(), key=lambda kv: -len(kv[1]))
    for uid, conn_names in rows:
        m = meta.get(uid, {})
        uname = m.get("username", "")
        first = m.get("first_name", "")
        last = m.get("last_name", "")
        full = " ".join(p for p in [first, last] if p).strip()
        if uname:
            label = "@" + esc(uname)
            if full:
                label += " (" + esc(full) + ")"
            link = _user_link(uid, label)
        elif full:
            link = "{} <code>id:{}</code>".format(_user_link(uid, esc(full)), uid)
        else:
            link = _user_link(uid, "id:{}".format(uid))
            if str(uid).startswith("w_"):
                link = "<code>id:{}</code>".format(uid)
        conns = ", ".join(esc(n) for n in conn_names[:6])
        if len(conn_names) > 6:
            conns += " +{}".format(len(conn_names) - 6)
        lines.append("\u2022 {} \u2014 {} ({})".format(link, len(conn_names), conns))
    text = "\n".join(lines)
    MAX = 4000
    chunks = []
    cur = ""
    for ln in text.split("\n"):
        if len(cur) + len(ln) + 1 > MAX:
            chunks.append(cur)
            cur = ln
        else:
            cur = (cur + "\n" + ln) if cur else ln
    if cur:
        chunks.append(cur)
    # Delete the preview message first, then send fresh
    try:
        await query.delete_message()
    except Exception:
        pass
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]])
    for i, ch in enumerate(chunks):
        is_last = (i == len(chunks) - 1)
        await context.bot.send_message(chat_id=chat_id, text=ch, parse_mode="HTML", disable_web_page_preview=True,
                                       reply_markup=back_kb if is_last else None)



PENDING_BCAST_FILE = Path(__file__).parent / "pending_broadcasts.json"

def _load_pending_bcast():
    import json as _j
    if not PENDING_BCAST_FILE.exists(): return {}
    try: return _j.loads(PENDING_BCAST_FILE.read_text())
    except Exception: return {}

def _save_pending_bcast(d):
    import json as _j
    PENDING_BCAST_FILE.write_text(_j.dumps(d, ensure_ascii=False))

async def _send_bcast_text(context, text, audience="all"):
    """Send text to all known users (from clients.json owners)."""
    import json as _j
    sent = 0; failed = 0
    try:
        clients = _j.loads(CLIENTS_FILE.read_text()) if CLIENTS_FILE.exists() else {}
    except Exception:
        clients = {}
    targets = sorted({int(rec["owner"]) for rec in clients.values() if rec.get("owner") and str(rec["owner"]).lstrip("-").isdigit()})
    for tg_id in targets:
        try:
            await context.bot.send_message(chat_id=tg_id, text=text, parse_mode="Markdown")
            sent += 1
        except Exception as _e:
            failed += 1
    return sent, failed

async def cb_bcast_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not is_admin(user.id): return
    bcast_id = query.data.split(":", 1)[1] if ":" in query.data else ""
    pending = _load_pending_bcast()
    rec = pending.get(bcast_id)
    if not rec:
        await query.edit_message_text("❌ Превью протухло, отправь заново.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]))
        return
    text = rec["text"]
    pending.pop(bcast_id, None)
    _save_pending_bcast(pending)
    await query.edit_message_text("⏳ Запускаю рассылку...")
    sent, failed = await _send_bcast_text(context, text)
    await query.edit_message_text(f"✅ Отправлено: {sent}, не доставлено: {failed}", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]))

async def cb_bcast_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    bcast_id = query.data.split(":", 1)[1] if ":" in query.data else ""
    pending = _load_pending_bcast()
    pending.pop(bcast_id, None)
    _save_pending_bcast(pending)
    await query.edit_message_text("❌ Рассылка отменена.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]))


# ──────────────────────────────────────────────────────────────────────────
# Stage 2 fix: handlers for diff alert buttons emitted by alert_bot.py.
# Kept out of Stage 1 intentionally — wired here now.
# ──────────────────────────────────────────────────────────────────────────

import uuid as _diff_uuid

SENT_ALERTS_DIR = BASE_DIR / "sent_alerts"


def _build_diff_broadcast_text(changed_categories: list, services_count) -> str:
    cats = ", ".join(changed_categories) if changed_categories else "несколько"
    return (
        "🔄 Обновились IP-списки сервисов\n\n"
        f"Категории с изменениями: {cats}.\n"
        f"Всего сервисов в каталоге: {services_count}.\n\n"
        "Если какие-то сервисы перестали работать — нужно перекачать конфиг:\n\n"
        "1. Открой этот чат\n"
        "2. Нажми 🆕 Новое подключение и создай свежий конфиг\n"
        "   (старый можешь удалить позже)\n"
        "3. В приложении Amnezia импортируй новый файл\n\n"
        "Если всё и так работает — конфиг менять не обязательно."
    )


async def cb_diff_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin pressed «📢 Сформировать рассылку» on the diff alert."""
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        return
    alert_id = q.data.split(":", 1)[1] if ":" in q.data else ""
    # Load archived alert context.
    alert_path = SENT_ALERTS_DIR / f"{alert_id}.json"
    changed, svc_count = [], "?"
    if alert_path.exists():
        try:
            a = json.loads(alert_path.read_text())
            changed = a.get("changed_categories", [])
            svc_count = a.get("services_count", "?")
        except Exception:
            pass
    text = _build_diff_broadcast_text(changed, svc_count)
    bcast_id = _diff_uuid.uuid4().hex[:12]
    pending = _load_pending_bcast()
    pending[bcast_id] = {"text": text}
    _save_pending_bcast(pending)
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("✅ Отправить всем", callback_data=f"bcast_send:{bcast_id}"),
        InlineKeyboardButton("❌ Отмена", callback_data=f"bcast_cancel:{bcast_id}"),
    ]])
    await q.edit_message_text(
        f"📢 *Черновик рассылки:*\n\n{text}",
        parse_mode="Markdown",
        reply_markup=kb,
    )


async def cb_diff_skip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin pressed «🔕 Пропустить» on the diff alert."""
    q = update.callback_query
    await q.answer("Пропущено")
    if not is_admin(q.from_user.id):
        return
    await q.edit_message_text(
        "🔕 Алерт пропущен. Следующий прилетит, когда списки снова изменятся.",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]),
    )


# ──────────────────────────────────────────────────────────────────────────
# Stage 3: /admin_domains — admin adds/removes domains that go into every
# new peer's AllowedIPs. Edits admin_domains.json (consumed by fetch_lists.py)
# and triggers an immediate in-process refresh so the change is visible
# on next peer creation without waiting for the hourly cron.
# ──────────────────────────────────────────────────────────────────────────

import re as _admindom_re
import asyncio as _admindom_asyncio

_DOMAIN_RE = _admindom_re.compile(
    r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
)


def _load_admin_domains():
    if not ADMIN_DOMAINS_FILE.exists():
        return []
    try:
        d = json.loads(ADMIN_DOMAINS_FILE.read_text())
        return sorted(d) if isinstance(d, list) else []
    except Exception:
        return []


def _save_admin_domains(domains):
    tmp = ADMIN_DOMAINS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(sorted(set(domains))))
    tmp.replace(ADMIN_DOMAINS_FILE)


def _validate_admin_domain(s):
    """Accept any reasonable user input and extract the hostname:

      'docker.com'              → 'docker.com'
      '  Docker.COM/  '         → 'docker.com'
      'https://openrouter.ai/'  → 'openrouter.ai'
      'http://example.com:8080/path?q=1' → 'example.com'
      'user@host.com'           → 'host.com'

    Returns None if no valid hostname can be extracted.
    """
    if not s:
        return None
    s = s.strip().lower()
    # Strip scheme if present (http://, https://, wg://, whatever).
    if "://" in s:
        s = s.split("://", 1)[1]
    # Strip userinfo (user@host).
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    # Strip path, query, fragment.
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    # Strip port.
    if ":" in s:
        s = s.split(":", 1)[0]
    # Trim surrounding dots/spaces again.
    s = s.strip(" .")
    if not s or len(s) > 253:
        return None
    if not _DOMAIN_RE.match(s):
        return None
    return s


def _fetch_lists_sync():
    """Import fetch_lists.py and run its main() in-process. Returns last log line."""
    import sys as _sys
    import importlib
    import io as _io
    import contextlib
    try:
        if "fetch_lists" in _sys.modules:
            fl = importlib.reload(_sys.modules["fetch_lists"])
        else:
            fl = importlib.import_module("fetch_lists")
        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                fl.main()
            except SystemExit:
                pass  # fetch_upstream raises SystemExit on sha256 mismatch
        out = buf.getvalue().strip().splitlines()
        return out[-1][:250] if out else "ok"
    except Exception as e:
        return f"fetch error: {e}"


async def _run_fetch_lists():
    """Async wrapper — run fetch_lists in thread pool so event loop isn't blocked."""
    loop = _admindom_asyncio.get_running_loop()
    try:
        return await _admindom_asyncio.wait_for(
            loop.run_in_executor(None, _fetch_lists_sync),
            timeout=45,
        )
    except _admindom_asyncio.TimeoutError:
        return "fetch timeout (DNS slow?)"


def _admindom_menu_text_and_kb():
    domains = _load_admin_domains()
    if domains:
        body = (
            "*Админ-домены*\n"
            "_в каждом новом конфиге_\n\n"
            + "\n".join(f"• `{d}`" for d in domains)
        )
    else:
        body = (
            "*Админ-домены*\n\n"
            "Пусто. Добавленные сюда домены попадают в `AllowedIPs` "
            "каждого _нового_ конфига для всех юзеров."
        )
    buttons = [[InlineKeyboardButton("➕ Добавить", callback_data="admindom_add")]]
    if domains:
        buttons.append([InlineKeyboardButton("➖ Удалить", callback_data="admindom_remove")])
    buttons.append([InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")])
    return body, InlineKeyboardMarkup(buttons)


async def cmd_admin_domains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    if not is_admin(user.id):
        return
    body, kb = _admindom_menu_text_and_kb()
    await update.message.reply_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_admindom_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        return
    body, kb = _admindom_menu_text_and_kb()
    await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_admindom_add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Entry point into WAITING_ADMIN_DOMAIN conversation state."""
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        return ConversationHandler.END
    await q.edit_message_text(
        "Введите домен (например: `docker.com`).",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Назад", callback_data="admindom_cancel")]]),
    )
    return WAITING_ADMIN_DOMAIN


async def cb_admindom_cancel_in_state(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Inline «⬅️ Назад» button exits WAITING_ADMIN_DOMAIN cleanly."""
    q = update.callback_query
    await q.answer()
    body, kb = _admindom_menu_text_and_kb()
    await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)
    return ConversationHandler.END


async def receive_admin_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return ConversationHandler.END
    raw = update.message.text or ""
    domain = _validate_admin_domain(raw)
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ К списку", callback_data="admindom_menu")]])
    retry_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Назад", callback_data="admindom_cancel")]])
    if not domain:
        await update.message.reply_text(
            "❌ Не похоже на домен. Пример: `docker.com`, `https://figma.com/`.\n"
            "Попробуй ещё раз или нажми кнопку ниже / `/cancel`.",
            parse_mode="Markdown",
            reply_markup=retry_kb,
        )
        return WAITING_ADMIN_DOMAIN
    domains = _load_admin_domains()
    if domain in domains:
        await update.message.reply_text(
            f"ℹ️ `{domain}` уже в списке.",
            parse_mode="Markdown",
            reply_markup=back_kb,
        )
        return ConversationHandler.END
    domains.append(domain)
    _save_admin_domains(domains)
    await update.message.reply_text(
        f"⏳ `{domain}` добавлен, обновляю списки…",
        parse_mode="Markdown",
    )
    result = await _run_fetch_lists()
    body, kb = _admindom_menu_text_and_kb()
    await update.message.reply_text(
        f"✅ `{domain}` добавлен\n`{result}`",
        parse_mode="Markdown",
    )
    await update.message.reply_text(body, parse_mode="Markdown", reply_markup=kb)
    return ConversationHandler.END


async def cb_admindom_remove(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        return
    domains = _load_admin_domains()
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ К списку", callback_data="admindom_menu")]])
    if not domains:
        await q.edit_message_text("Список пуст.", reply_markup=back_kb)
        return
    buttons = [[InlineKeyboardButton(f"🗑 {d}", callback_data=f"admindom_del:{d}")]
               for d in domains[:20]]
    buttons.append([InlineKeyboardButton("⬅️ Назад", callback_data="admindom_menu")])
    await q.edit_message_text(
        "Какой удалить?",
        reply_markup=InlineKeyboardMarkup(buttons),
    )


async def cb_admindom_del(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        return
    domain = q.data.split(":", 1)[1] if ":" in q.data else ""
    domains = _load_admin_domains()
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ К списку", callback_data="admindom_menu")]])
    if domain not in domains:
        await q.edit_message_text("ℹ️ Не найден.", reply_markup=back_kb)
        return
    domains.remove(domain)
    _save_admin_domains(domains)
    await q.edit_message_text(
        f"⏳ `{domain}` удалён, обновляю списки…",
        parse_mode="Markdown",
    )
    result = await _run_fetch_lists()
    await q.edit_message_text(
        f"✅ `{domain}` удалён\n`{result}`",
        parse_mode="Markdown",
        reply_markup=back_kb,
    )


# ──────────────────────────────────────────────────────────────────────────
# PR 1: /my_domains — any authorized user can add personal domains that go
# into THEIR peer configs only. fetch_lists.py resolves the list hourly;
# generate_client_config(user_id=...) appends the per-user CIDRs.
#
# Promoter: if the same domain gets added by ≥ POPULAR_THRESHOLD unique
# users, fire an alert to the admin offering to move it to the global
# admin_domains.json. Once admin clicks promote → domain migrates (removed
# from every user's list, added to admin list, re-fetched). Click skip →
# domain marked as skipped, no more alerts.
# ──────────────────────────────────────────────────────────────────────────


def _load_user_domains() -> dict:
    if not USER_DOMAINS_FILE.exists():
        return {}
    try:
        d = json.loads(USER_DOMAINS_FILE.read_text())
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_user_domains(data: dict):
    tmp = USER_DOMAINS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, sort_keys=True))
    tmp.replace(USER_DOMAINS_FILE)


def _get_user_domain_list(user_id: int) -> list:
    """Return sorted list of domain strings for a user (compat with old API)."""
    entries = ud.list_domains(USER_DOMAINS_FILE, str(user_id))
    return sorted(e["domain"] for e in entries if isinstance(e, dict) and "domain" in e)


def _set_user_domain_list(user_id: int, domains: list):
    """Set user's domain list (list of strings). Existing entries with the
    same domain preserve their resolved IPs; new domains are resolved now."""
    uid = str(user_id)
    by_domain = {}
    try:
        raw = _load_user_domains()
        for e in raw.get(uid, []):
            if isinstance(e, dict) and "domain" in e:
                by_domain[e["domain"]] = e
    except Exception:
        pass

    new_entries = []
    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for d in domains:
        if d in by_domain:
            new_entries.append(by_domain[d])
        else:
            v4, v6 = _resolve_dns_now(d)
            new_entries.append({
                "domain": d,
                "ips_v4": v4,
                "ips_v6": v6,
                "resolved_at": now_iso,
            })

    data = _load_user_domains()
    if new_entries:
        data[uid] = new_entries
    else:
        data.pop(uid, None)
    _save_user_domains(data)


def _resolve_dns_now(domain: str):
    """Synchronous DNS resolution for a single domain. Returns (v4_list, v6_list)."""
    import socket
    v4 = []
    v6 = []
    try:
        v4 = sorted({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        v6 = sorted({r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception:
        pass
    return v4, v6


def _load_popular() -> dict:
    if not POPULAR_DOMAINS_FILE.exists():
        return {}
    try:
        d = json.loads(POPULAR_DOMAINS_FILE.read_text())
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_popular(data: dict):
    tmp = POPULAR_DOMAINS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, sort_keys=True))
    tmp.replace(POPULAR_DOMAINS_FILE)


async def _maybe_alert_promoter(context, domain: str, users: list):
    """If the domain just crossed POPULAR_THRESHOLD and hasn't been alerted/
    skipped/promoted before, send the admin a TG message with promote/skip
    buttons. Flags are persisted in popular_domains.json so we never alert
    twice for the same domain."""
    popular = _load_popular()
    entry = popular.get(domain, {})
    if entry.get("promoted") or entry.get("skipped") or entry.get("alerted"):
        return
    if len(users) < POPULAR_THRESHOLD:
        return

    entry.update({
        "users": sorted(set(users)),
        "alerted": True,
        "alerted_at": int(time.time()),
    })
    popular[domain] = entry
    _save_popular(popular)

    user_labels = ", ".join(format_user_label(uid) for uid in entry["users"])
    text = (
        f"📈 *Домен в тренде*\n\n"
        f"`{domain}` добавили **{len(entry['users'])}** юзеров: {user_labels}.\n\n"
        f"Перенести в общий список (_admin_domains_)? "
        f"Тогда домен будет в конфиге у каждого — и у тех, кто его не добавлял."
    )
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("➕ В общий список", callback_data=f"promote_domain:{domain}"),
        InlineKeyboardButton("🔕 Пропустить",    callback_data=f"promote_skip:{domain}"),
    ]])
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                chat_id=admin_id,
                text=text,
                parse_mode="Markdown",
                reply_markup=kb,
            )
        except Exception as e:
            logger.warning(f"promoter alert failed for admin {admin_id}: {e}")


def _track_domain_usage(user_id: int, domain: str) -> list:
    """Append user_id to popular_domains[domain].users (dedup). Return the
    current unique users list so the caller can check the threshold."""
    popular = _load_popular()
    entry = popular.get(domain, {"users": [], "alerted": False, "skipped": False, "promoted": False})
    users = sorted(set(entry.get("users", []) + [user_id]))
    entry["users"] = users
    popular[domain] = entry
    _save_popular(popular)
    return users


def _user_can_use_mydomains(user_id: int) -> bool:
    return is_admin(user_id) or invites.is_allowed(user_id)


def _mydom_menu_text_and_kb(user_id: int):
    domains = _get_user_domain_list(user_id)
    if domains:
        body = (
            "*Мои домены*\n"
            "_попадают только в твои конфиги_\n\n"
            + "\n".join(f"• `{d}`" for d in domains)
        )
    else:
        body = (
            "*Мои домены*\n\n"
            "Тут пусто. Добавленные домены будут попадать в `AllowedIPs` "
            "всех твоих подключений — и новых, и уже существующих (достаточно "
            "перекачать конфиг после добавления).\n\n"
            f"Лимит: {MAX_DOMAINS_PER_USER} доменов."
        )
    buttons = [[InlineKeyboardButton("➕ Добавить", callback_data="mydom_add")]]
    if domains:
        buttons.append([InlineKeyboardButton("➖ Удалить", callback_data="mydom_remove")])
    buttons.append([InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")])
    return body, InlineKeyboardMarkup(buttons)


# ── /subscription — HAPP subscription URL ──────────────────────────────

SUBSCRIPTION_BASE_URL = "https://baton.telescope.cv:4443/sub/"
SUBSCRIPTION_INSTALL_URL = "https://baton.telescope.cv:4443/install/"


def _sub_menu_text_and_kb(user_id: int):
    """Return (text, keyboard) for the subscription menu."""
    meta = load_users_meta()
    user_meta = meta.get(str(user_id), {})
    sub = user_meta.get("xray_sub")
    if sub and sub.get("secret"):
        install_url = SUBSCRIPTION_INSTALL_URL + sub["secret"]
        body = (
            "📡 *Твоя HAPP-подписка готова.*\n\n"
            "Жми кнопку ниже — HAPP откроется и добавит подписку автоматически. "
            "Дальше включи VPN прямо в приложении.\n\n"
            "Роутинг обновляется сам каждый час — ничего вручную делать не нужно."
        )
        rows = [
            [InlineKeyboardButton("📲 Установить в HAPP", url=install_url)],
            [InlineKeyboardButton("🔄 Сбросить ссылку", callback_data="subscription_rotate")],
            [InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")],
        ]
    else:
        body = (
            "📡 *HAPP-подписка*\n\n"
            "Создать персональную подписку для HAPP? После установки VPN будет "
            "обновляться сам — добавленные домены и свежий роутинг подтянутся автоматически."
        )
        rows = [
            [InlineKeyboardButton("✅ Создать подписку", callback_data="subscription_create")],
            [InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")],
        ]
    return body, InlineKeyboardMarkup(rows)


async def cmd_subscription(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    body, kb = _sub_menu_text_and_kb(user.id)
    await update.message.reply_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_subscription_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    body, kb = _sub_menu_text_and_kb(q.from_user.id)
    try:
        await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)
    except Exception:
        await q.message.reply_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_subscription_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Создаю подписку…")
    try:
        create_xray_sub(q.from_user)
    except xm.XrayError as e:
        logger.warning(f"subscription create failed: {e!r}")
        await q.edit_message_text(
            "❌ Не могу создать подписку: XRay временно недоступен. Попробуй через минуту.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]
            ),
        )
        return
    body, kb = _sub_menu_text_and_kb(q.from_user.id)
    await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_subscription_rotate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Сбрасываю URL…")
    rotate_xray_sub(q.from_user)
    body, kb = _sub_menu_text_and_kb(q.from_user.id)
    tail = "\n\n✅ *URL сброшен.* Старый больше не работает — обнови в HAPP."
    await q.edit_message_text(body + tail, parse_mode="Markdown", reply_markup=kb)


async def cmd_my_domains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    if not _user_can_use_mydomains(user.id):
        await update.message.reply_text(
            "🔒 Нет доступа. Попроси приглашение у админа.",
            reply_markup=main_menu_keyboard(user.id),
        )
        return
    body, kb = _mydom_menu_text_and_kb(user.id)
    await update.message.reply_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_mydom_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not _user_can_use_mydomains(q.from_user.id):
        return
    body, kb = _mydom_menu_text_and_kb(q.from_user.id)
    await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)


def _pro_submenu_body_and_kb():
    """Pro-mode preset submenu text + keyboard. Extracted so receive_my_domain
    can rewind here after an add."""
    social_cats = _category_pretty_list(PRESET_CATEGORIES["social"])
    social_ai_cats = _category_pretty_list(PRESET_CATEGORIES["social-ai"])
    body = (
        "*Pro-режим* — какой набор сервисов?\n\n"
        f"\U0001F4AC *Общение + видео*\n  _{social_cats}_\n\n"
        f"\U0001F916 *+ нейросети*\n  _{social_ai_cats}_\n\n"
        "\u2699\uFE0F *Свой набор* — выбрать категории чекбоксами\n\n"
        "Твои домены (🌐 Мои домены) и общий админский список "
        "всегда склеиваются поверх пресета."
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("\U0001F4AC Общение + видео", callback_data="new_preset_social")],
        [InlineKeyboardButton("\U0001F916 + нейросети", callback_data="new_preset_social-ai")],
        [InlineKeyboardButton("\u2699\uFE0F Свой набор", callback_data="new_preset_custom")],
        [InlineKeyboardButton("\U0001F310 Добавить свой домен", callback_data="mydom_add:pro")],
        [InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="new_client")],
    ])
    return body, kb


async def _send_return_after_mydom(update, context):
    """Route the user to wherever they came from after /my_domains flow ends.
    context.user_data['mydom_return_to'] — one of 'pro' / 'custom' / None."""
    return_to = context.user_data.pop("mydom_return_to", None)
    chat = update.effective_chat if hasattr(update, "effective_chat") else None
    msg = update.message if hasattr(update, "message") and update.message else (
        update.callback_query.message if getattr(update, "callback_query", None) else None
    )
    if return_to == "pro" and msg is not None:
        body, kb = _pro_submenu_body_and_kb()
        await msg.reply_text(body, parse_mode="Markdown", reply_markup=kb)
        return
    if return_to == "custom" and msg is not None:
        sel = set(context.user_data.get("custom_cats") or set())
        await msg.reply_text(
            "*Свой набор* — выбери нужные категории (можно несколько):",
            parse_mode="Markdown",
            reply_markup=_render_custom_keyboard(sel),
        )
        return
    # Default — back to mydom menu as before.
    user_id = update.effective_user.id
    body, kb = _mydom_menu_text_and_kb(user_id)
    if msg is not None:
        await msg.reply_text(body, parse_mode="Markdown", reply_markup=kb)


async def cb_mydom_add(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not _user_can_use_mydomains(q.from_user.id):
        return ConversationHandler.END
    if len(_get_user_domain_list(q.from_user.id)) >= MAX_DOMAINS_PER_USER:
        await q.edit_message_text(
            f"Лимит {MAX_DOMAINS_PER_USER} доменов достигнут. Удали ненужное, прежде чем добавить новое.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️", callback_data="mydom_menu")]]),
        )
        return ConversationHandler.END
    # Parse optional return target: mydom_add:pro / mydom_add:custom
    parts = q.data.split(":", 1)
    return_to = parts[1] if len(parts) == 2 else None
    if return_to in ("pro", "custom"):
        context.user_data["mydom_return_to"] = return_to
    else:
        context.user_data.pop("mydom_return_to", None)
    await q.edit_message_text(
        "Введите домен (например: `docker.com`).",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Назад", callback_data="mydom_cancel")]]),
    )
    return WAITING_MY_DOMAIN


async def cb_mydom_cancel_in_state(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Inline «⬅️ Назад» button that exits WAITING_MY_DOMAIN cleanly.
    Respects mydom_return_to — rewinds to Pro / custom picker if set."""
    q = update.callback_query
    await q.answer()
    return_to = context.user_data.pop("mydom_return_to", None)
    if return_to == "pro":
        body, kb = _pro_submenu_body_and_kb()
        await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)
    elif return_to == "custom":
        sel = set(context.user_data.get("custom_cats") or set())
        await q.edit_message_text(
            "*Свой набор* — выбери нужные категории (можно несколько):",
            parse_mode="Markdown",
            reply_markup=_render_custom_keyboard(sel),
        )
    else:
        body, kb = _mydom_menu_text_and_kb(q.from_user.id)
        await q.edit_message_text(body, parse_mode="Markdown", reply_markup=kb)
    return ConversationHandler.END


async def receive_my_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not _user_can_use_mydomains(user.id):
        return ConversationHandler.END
    raw = update.message.text or ""
    domain = _validate_admin_domain(raw)  # same regex works for per-user
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ К списку", callback_data="mydom_menu")]])
    retry_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Назад", callback_data="mydom_cancel")]])
    if not domain:
        # Stay in state — user can just retype correct domain or tap back.
        await update.message.reply_text(
            "❌ Не похоже на домен. Пример: `docker.com`, `https://figma.com/`.\n"
            "Попробуй ещё раз или нажми кнопку ниже / `/cancel`.",
            parse_mode="Markdown",
            reply_markup=retry_kb,
        )
        return WAITING_MY_DOMAIN

    # Global list already has it? — no point adding to personal.
    admin_list = _load_admin_domains()
    if domain in admin_list:
        await update.message.reply_text(
            f"ℹ️ `{domain}` уже в *общем списке* — он и так попадает в твой конфиг.",
            parse_mode="Markdown",
            reply_markup=back_kb,
        )
        return ConversationHandler.END

    domains = _get_user_domain_list(user.id)
    if domain in domains:
        await update.message.reply_text(
            f"ℹ️ `{domain}` уже в твоём списке.",
            parse_mode="Markdown",
            reply_markup=back_kb,
        )
        return ConversationHandler.END

    domains.append(domain)
    _set_user_domain_list(user.id, domains)
    total_users = _track_domain_usage(user.id, domain)

    await update.message.reply_text(
        f"⏳ `{domain}` добавлен, обновляю списки…",
        parse_mode="Markdown",
    )
    result = await _run_fetch_lists()
    await update.message.reply_text(
        f"✅ `{domain}` добавлен — перекачай любой свой конфиг, чтобы IP попал в него.\n`{result}`",
        parse_mode="Markdown",
    )
    # Popularity alert — notify admin if threshold just crossed.
    await _maybe_alert_promoter(context, domain, total_users)

    # PR 2.5.2: route back to Pro / custom picker if user came from there.
    await _send_return_after_mydom(update, context)
    return ConversationHandler.END


async def cb_mydom_remove(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not _user_can_use_mydomains(q.from_user.id):
        return
    domains = _get_user_domain_list(q.from_user.id)
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ К списку", callback_data="mydom_menu")]])
    if not domains:
        await q.edit_message_text("Список пуст.", reply_markup=back_kb)
        return
    buttons = [[InlineKeyboardButton(f"🗑 {d}", callback_data=f"mydom_del:{d}")] for d in domains]
    buttons.append([InlineKeyboardButton("⬅️ Назад", callback_data="mydom_menu")])
    await q.edit_message_text("Какой удалить?", reply_markup=InlineKeyboardMarkup(buttons))


async def cb_mydom_del(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not _user_can_use_mydomains(q.from_user.id):
        return
    domain = q.data.split(":", 1)[1] if ":" in q.data else ""
    domains = _get_user_domain_list(q.from_user.id)
    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ К списку", callback_data="mydom_menu")]])
    if domain not in domains:
        await q.edit_message_text("ℹ️ Не найден.", reply_markup=back_kb)
        return
    domains.remove(domain)
    _set_user_domain_list(q.from_user.id, domains)

    # Drop user from popular_domains tracker — they no longer use this domain.
    popular = _load_popular()
    entry = popular.get(domain)
    if entry:
        users = [u for u in entry.get("users", []) if u != q.from_user.id]
        entry["users"] = sorted(set(users))
        popular[domain] = entry
        _save_popular(popular)

    await q.edit_message_text(
        f"⏳ `{domain}` удалён, обновляю списки…",
        parse_mode="Markdown",
    )
    result = await _run_fetch_lists()
    await q.edit_message_text(
        f"✅ `{domain}` удалён\n`{result}`",
        parse_mode="Markdown",
        reply_markup=back_kb,
    )


async def cb_promote_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin accepts promotion: domain → admin_domains, cleaned from everyone's
    user_domains, flagged in popular as promoted."""
    q = update.callback_query
    await q.answer()
    if not is_admin(q.from_user.id):
        return
    domain = q.data.split(":", 1)[1] if ":" in q.data else ""
    # 1. Add to admin list (dedup).
    admin_list = _load_admin_domains()
    if domain not in admin_list:
        admin_list.append(domain)
        _save_admin_domains(admin_list)
    # 2. Drop from each user's list (they inherit via admin).
    udata = _load_user_domains()
    for uid_str, entries in list(udata.items()):
        if not isinstance(entries, list):
            continue
        has = any(isinstance(e, dict) and e.get("domain") == domain for e in entries)
        if has:
            new = [e for e in entries
                   if not (isinstance(e, dict) and e.get("domain") == domain)]
            if new:
                udata[uid_str] = new
            else:
                udata.pop(uid_str, None)
    _save_user_domains(udata)
    # 3. Mark promoted in popular tracker.
    popular = _load_popular()
    entry = popular.get(domain, {})
    entry.update({"promoted": True, "promoted_at": int(time.time())})
    popular[domain] = entry
    _save_popular(popular)

    await q.edit_message_text(f"⏳ `{domain}` → общий список, обновляю…", parse_mode="Markdown")
    result = await _run_fetch_lists()
    await q.edit_message_text(
        f"✅ `{domain}` теперь в общем списке — попадёт в конфиг каждому юзеру.\n`{result}`",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]),
    )


async def cb_promote_skip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Пропущено")
    if not is_admin(q.from_user.id):
        return
    domain = q.data.split(":", 1)[1] if ":" in q.data else ""
    popular = _load_popular()
    entry = popular.get(domain, {})
    entry["skipped"] = True
    entry["skipped_at"] = int(time.time())
    popular[domain] = entry
    _save_popular(popular)
    await q.edit_message_text(
        f"🔕 `{domain}` пропущен. В общий список не добавляю, у юзеров в их личных списках остаётся.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back_menu")]]),
    )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    args = context.args if hasattr(context, "args") else []
    logger.info(f"cmd_start from {user.id} (@{user.username}) args={args}")
    if args:
        token = args[0].strip()
        logger.info(f"redeeming token={token} for user={user.id}")
        ok, msg = invites.redeem_token(token, user.id)
        if ok:
            await update.message.reply_text(f"✅ {msg}")
        else:
            if not invites.is_allowed(user.id):
                await update.message.reply_text(f"❌ {msg}\n\nПопросите у знакомого рабочую пригласительную ссылку.")
                return
    if not is_admin(user.id) and not invites.is_allowed(user.id):
        await update.message.reply_text(
            "🔒 Доступ к боту только по приглашению.\n\n"
            "Попросите у знакомого, который уже пользуется сервисом, прислать вам пригласительную ссылку."
        )
        return
    save_user_meta(user)
    seen = load_seen_users()
    first_time = user.id not in seen

    if first_time:
        save_seen_user(user.id)
        await update.message.reply_text(
            f"\U0001F44B *Добро пожаловать в КВН!*\n\n"
            f"Привет, {_esc_md(user.first_name)}! Это сервис для обхода блокировок.\n\n"
            "\U0001F4F2 *Как начать:*\n"
            "1. Нажмите *Новое подключение*\n"
            "2. Придумайте имя (например: phone, laptop)\n"
            "3. Получите файл и откройте в приложении Amnezia\n\n"
            f"\U0001F310 Резервный сайт: https://{SERVER_IP}:4443\n\n"
            "Вопросы? Нажмите *Написать админу*.",
            parse_mode="Markdown",
        )

    await update.message.reply_text(
        f"\U0001F510 *КВН*\n\n"
        f"\U0001F310 *Резервный сайт (если Telegram недоступен):*\n"
        f"`https://{SERVER_IP}:4443`\n"
        "\u26A0\uFE0F Откройте в браузере (Safari / Chrome), не в Telegram. "
        "Браузер покажет \u00abНебезопасный сертификат\u00bb \u2014 это нормально, "
        "нажмите \u00abПродолжить\u00bb. Сертификат самоподписанный для шифрования передачи ключей.\n\n"
        "\U0001F4F2 *Скачать приложение:*\n"
        "\U0001F4F1 Android \u2014 [AmneziaVPN](https://play.google.com/store/apps/details?id=org.amnezia.vpn)\n"
        "\U0001F34F iPhone (иностр.) \u2014 [AmneziaVPN](https://apps.apple.com/app/amneziavpn/id1600529900)\n"
        "\U0001F34F iPhone (рос.) \u2014 [AmneziaWG](https://apps.apple.com/ru/app/amneziawg/id6478942365)\n\n"
        f"Выбери действие:",
        reply_markup=main_menu_keyboard(user.id),
        parse_mode="Markdown",
    )


async def cmd_new(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    user_clients = get_user_clients(user.id)
    if not is_admin(user.id) and len(user_clients) >= MAX_CONNECTIONS:
        await update.message.reply_text(
            f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).\n"
            "Удалите одно из существующих, чтобы создать новое.",
            reply_markup=main_menu_keyboard(user.id),
        )
        return
    buttons = [
        [InlineKeyboardButton("\U0001F7E2 Amnezia (рекомендуется)", callback_data="new_split")],
        [InlineKeyboardButton("\U0001F1F7\U0001F1FA Amnezia через РФ-хоп", callback_data="new_rus")],
        [InlineKeyboardButton("\U0001F198 Чистый — если первый не работает", callback_data="new_clean")],
        [InlineKeyboardButton("\U0001F4E1 HAPP (iOS/Android)", callback_data="subscription_menu")],
        [InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")],
    ]
    await update.message.reply_text(
        "Какой тип подключения создать?\n\n"
        "\U0001F7E2 *Amnezia* — через сервер идёт только нужный трафик, "
        "российские сервисы работают напрямую\n"
        "\U0001F198 *Чистый* — весь трафик через сервер, помогает когда первый не работает "
        "(но российские банки/госуслуги могут блокировать вход)\n"
        "\U0001F4E1 *HAPP* — альтернативный клиент через VLESS+Reality, роутинг обновляется сам",
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode="Markdown",
    )


async def cmd_my(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    user_clients = get_user_clients(user.id)
    if not user_clients:
        await update.message.reply_text(
            "У вас пока нет подключений.",
            reply_markup=main_menu_keyboard(user.id),
        )
        return
    buttons = []
    for name, info in user_clients.items():
        buttons.append([InlineKeyboardButton(
            f"\U0001F4F1 {name} \u2014 {info['ip']}",
            callback_data=f"view_{name}",
        )])
    buttons.append([InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")])
    await update.message.reply_text(
        "\U0001F4CB *Ваши подключения:*",
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode="Markdown",
    )


async def cmd_verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    save_user_meta(update.effective_user)
    if not context.args:
        await update.message.reply_text("Использование: /verify КОД")
        return

    code = context.args[0].strip().lower()
    user = update.effective_user
    web_users = load_json(WEB_USERS_FILE)

    found_username = None
    for username, udata in web_users.items():
        if udata.get("verify_code", "").lower() == code and not udata.get("verified"):
            found_username = username
            break

    if not found_username:
        await update.message.reply_text("\u274c Код не найден или уже использован.")
        return

    web_users[found_username]["verified"] = True
    web_users[found_username]["tg_id"] = user.id
    save_json(WEB_USERS_FILE, web_users)

    # Migrate web connections to real tg_id
    clients = load_clients()
    prefix = f"w_{found_username}_"
    migrated = 0
    for name, info in clients.items():
        if info.get("owner") == f"w_{found_username}":
            info["owner"] = user.id
            migrated += 1
    save_clients(clients)

    logger.info(
        f"VERIFY: web user '{found_username}' verified by @{user.username or '?'} "
        f"(id={user.id}), migrated {migrated} connections"
    )

    await update.message.reply_text(
        f"\u2705 Аккаунт *{found_username}* верифицирован!\n"
        f"Перенесено подключений: {migrated}\n"
        f"Теперь вам доступно до {MAX_CONNECTIONS} подключений.",
        reply_markup=main_menu_keyboard(user.id),
        parse_mode="Markdown",
    )


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    save_user_meta(query.from_user)
    user_id = query.from_user.id
    data = query.data

    if data == "new_client":
        user_clients = get_user_clients(user_id)
        if not is_admin(user_id) and len(user_clients) >= MAX_CONNECTIONS:
            await query.edit_message_text(
                f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).\n"
                "Удалите одно из существующих.",
                reply_markup=main_menu_keyboard(user_id),
            )
            return ConversationHandler.END
        # Show submenu — pick connection style
        buttons = [
            [InlineKeyboardButton("\U0001F7E2 Amnezia (рекомендуется)", callback_data="new_split")],
            [InlineKeyboardButton("\U0001F1F7\U0001F1FA Amnezia через РФ-хоп", callback_data="new_rus")],
            [InlineKeyboardButton("\U0001F39B Pro-режим", callback_data="new_pro")],
            [InlineKeyboardButton("\U0001F198 Чистый — если первый не работает", callback_data="new_clean")],
            [InlineKeyboardButton("\U0001F4E1 HAPP (iOS/Android)", callback_data="subscription_menu")],
            [InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")],
        ]
        await query.edit_message_text(
            "Какой тип подключения создать?\n\n"
            "\U0001F7E2 *Amnezia* — через сервер идёт только нужный трафик\n"
            "\U0001F39B *Pro-режим* — выбрать конкретный набор сервисов\n"
            "\U0001F198 *Чистый* — весь трафик через сервер, помогает когда первый тормозит "
            "(но российские банки/госуслуги могут блокировать вход)\n"
            "\U0001F4E1 *HAPP* — альтернативный клиент через VLESS+Reality, роутинг обновляется сам",
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="Markdown",
        )
        return

    elif data == "new_pro":
        # PR 2: preset submenu. Single source of truth for body+kb is
        # _pro_submenu_body_and_kb() so the return-from-mydom path shows
        # the exact same screen.
        user_clients = get_user_clients(user_id)
        if not is_admin(user_id) and len(user_clients) >= MAX_CONNECTIONS:
            await query.edit_message_text(
                f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).",
                reply_markup=main_menu_keyboard(user_id),
            )
            return ConversationHandler.END
        body, kb = _pro_submenu_body_and_kb()
        await query.edit_message_text(body, reply_markup=kb, parse_mode="Markdown")
        return

    elif data == "new_preset_custom":
        # Open the category-picker keyboard.
        user_clients = get_user_clients(user_id)
        if not is_admin(user_id) and len(user_clients) >= MAX_CONNECTIONS:
            await query.edit_message_text(
                f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).",
                reply_markup=main_menu_keyboard(user_id),
            )
            return ConversationHandler.END
        context.user_data["custom_cats"] = set()
        await query.edit_message_text(
            "*Свой набор* — выбери нужные категории (можно несколько):",
            reply_markup=_render_custom_keyboard(set()),
            parse_mode="Markdown",
        )
        return

    elif data.startswith("new_preset_"):
        # Enter peer-creation flow with a specific preset.
        user_clients = get_user_clients(user_id)
        if not is_admin(user_id) and len(user_clients) >= MAX_CONNECTIONS:
            await query.edit_message_text(
                f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).",
                reply_markup=main_menu_keyboard(user_id),
            )
            return ConversationHandler.END
        preset = data[len("new_preset_"):]
        if preset not in PRESET_CATEGORIES:
            await query.edit_message_text(
                "Неизвестный пресет.",
                reply_markup=main_menu_keyboard(user_id),
            )
            return ConversationHandler.END
        context.user_data["mode"] = "split"
        context.user_data["preset"] = preset
        label = PRESET_LABELS.get(preset, preset)
        await query.edit_message_text(
            f"\U0001F4DD Введите имя подключения для пресета «{label}»:",
        )
        return WAITING_NAME

    elif data in ("new_split", "new_clean", "new_rus"):
        user_clients = get_user_clients(user_id)
        if not is_admin(user_id) and len(user_clients) >= MAX_CONNECTIONS:
            await query.edit_message_text(
                f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).",
                reply_markup=main_menu_keyboard(user_id),
            )
            return ConversationHandler.END
        mode = {"new_clean": "full", "new_youtube": "youtube"}.get(data, "split")
        context.user_data["mode"] = mode
        context.user_data.pop("preset", None)  # legacy flows never use preset
        context.user_data["rus_hop"] = (data == "new_rus")
        kind = {"full": "чистого", "youtube": "YouTube", "split": "обычного"}[mode]
        if data == "new_rus":
            kind = "обычного через РФ-хоп"
        await query.edit_message_text(f"\U0001F4DD Введите имя {kind} подключения:")
        return WAITING_NAME

    elif data == "my_clients":
        # Always show only the caller's own clients (even for admin)
        all_clients = load_clients()
        own_clients = {n: c for n, c in all_clients.items() if c.get("owner") == user_id}
        if not own_clients:
            await query.edit_message_text(
                "У вас пока нет подключений.",
                reply_markup=main_menu_keyboard(user_id),
            )
            return
        buttons = []
        for name, info in own_clients.items():
            buttons.append([InlineKeyboardButton(
                f"\U0001F4F1 {name} \u2014 {info['ip']}",
                callback_data=f"view_{name}",
            )])
        buttons.append([InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")])
        await query.edit_message_text(
            "\U0001F4CB Ваши подключения:",
            reply_markup=InlineKeyboardMarkup(buttons),
        )

    elif data == "all_clients":
        if not is_admin(user_id):
            await query.edit_message_text("Нет доступа.", reply_markup=main_menu_keyboard(user_id))
            return
        clients = load_clients()
        if not clients:
            await query.edit_message_text(
                "Подключений нет.",
                reply_markup=main_menu_keyboard(user_id),
            )
            return
        buttons = []
        for name, info in sorted(clients.items()):
            owner = info.get("owner", "?")
            owner_label = format_user_label(owner) if isinstance(owner, int) else str(owner)
            buttons.append([InlineKeyboardButton(
                f"\U0001F4F1 {name} \u2014 {info['ip']} \u2014 {owner_label}",
                callback_data=f"view_{name}",
            )])
        buttons.append([InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")])
        await query.edit_message_text(
            f"\U0001F4CB Все подключения ({len(clients)}):",
            reply_markup=InlineKeyboardMarkup(buttons),
        )

    elif data.startswith("view_"):
        name = data[5:]
        clients = load_clients()
        info = clients.get(name)
        if not info or (info.get("owner") != user_id and not is_admin(user_id)):
            await query.edit_message_text("Подключение не найдено.",
                                          reply_markup=main_menu_keyboard(user_id))
            return
        buttons = [
            [InlineKeyboardButton("\U0001F4E5 Скачать конфиг", callback_data=f"dl_{name}")],
            [InlineKeyboardButton("\U0001F1F7\U0001F1FA РФ-хоп (если не работает первый вариант)", callback_data=f"dl_rus_{name}")],
            [InlineKeyboardButton("\U0001F5D1 Удалить", callback_data=f"confirmdel_{name}")],
            [InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="my_clients")],
        ]
        _tunnel = info.get("tunnel")
        if _tunnel == "full":
            tunnel_kind = "чистый (весь трафик)"
        elif info.get("preset") == "custom":
            _cats = info.get("custom_categories") or []
            tunnel_kind = f"свой набор ({_category_pretty_list(_cats) or 'пусто'})"
        elif info.get("preset"):
            tunnel_kind = f"Pro-режим: {PRESET_LABELS.get(info['preset'], info['preset'])}"
        else:
            tunnel_kind = "Amnezia (всё)"
        if info.get("rus_hop"):
            tunnel_kind += " 🇷🇺 РФ-хоп"
        owner_line = ""
        if is_admin(user_id):
            owner = info.get("owner")
            owner_line = f"\nВладелец: {format_user_label(owner) if isinstance(owner, int) else owner}"
        await query.edit_message_text(
            f"\U0001F4F1 *{name}*\nIP: `{info['ip']}`\nТип: {tunnel_kind}{owner_line}",
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="Markdown",
        )

    elif data.startswith("dl_rus_"):
        name = data[7:]
        clients = load_clients()
        info = clients.get(name)
        if not info or (info.get("owner") != user_id and not is_admin(user_id)):
            await query.edit_message_text("Подключение не найдено.",
                                          reply_markup=main_menu_keyboard(user_id))
            return
        tunnel = info.get("tunnel", "split")
        if tunnel is True: tunnel = "full"
        elif tunnel is False: tunnel = "split"
        peer_owner = info.get("owner")
        peer_preset = info.get("preset")
        peer_custom_cats = info.get("custom_categories")
        client_conf = generate_client_config(
            info["privkey"], info["ip"], info["psk"], mode=tunnel,
            user_id=peer_owner if isinstance(peer_owner, int) else None,
            preset=peer_preset,
            custom_categories=peer_custom_cats,
            endpoint_override=RUS_HOP_ENDPOINT,
        )
        caption = (
            "\U0001F1F7\U0001F1FA *Конфиг через РФ-хоп*\n"
            f"Endpoint: `{RUS_HOP_ENDPOINT}`\n"
            "Трафик проходит через российский сервер-релей, потом на наш VPN.\n"
            "Используй если домашний/мобильный провайдер блочит прямой коннект к VPN.\n\n"
        ) + build_caption(name, info["ip"])
        prefix_map = {"full": "clean_", "youtube": "youtube_"}
        prefix = "rus_" + prefix_map.get(tunnel, "")
        filename = f"{prefix}{name}.conf"
        await query.message.reply_document(
            document=io.BytesIO(client_conf.encode()),
            filename=filename,
            caption=caption,
            parse_mode="Markdown",
        )

    elif data.startswith("dl_"):
        name = data[3:]
        clients = load_clients()
        info = clients.get(name)
        if not info or (info.get("owner") != user_id and not is_admin(user_id)):
            await query.edit_message_text("Подключение не найдено.",
                                          reply_markup=main_menu_keyboard(user_id))
            return
        tunnel = info.get("tunnel", "split")
        if tunnel is True: tunnel = "full"
        elif tunnel is False: tunnel = "split"
        peer_owner = info.get("owner")
        peer_preset = info.get("preset")  # None for legacy peers = flat list
        peer_custom_cats = info.get("custom_categories")
        _ep_override = RUS_HOP_ENDPOINT if info.get("rus_hop") else None
        client_conf = generate_client_config(
            info["privkey"], info["ip"], info["psk"], mode=tunnel,
            user_id=peer_owner if isinstance(peer_owner, int) else None,
            preset=peer_preset,
            custom_categories=peer_custom_cats,
            endpoint_override=_ep_override,
        )
        caption = build_caption(name, info["ip"])
        if tunnel == "full":
            caption = (
                "\u26a0\ufe0f *Чистый конфиг* — весь трафик через сервер.\n\n"
            ) + caption
        elif tunnel == "youtube":
            caption = (
                "\U0001F3AC *YouTube-конфиг* — через сервер идёт только Google/YouTube.\n\n"
            ) + caption
        prefix = {"full": "clean_", "youtube": "youtube_"}.get(tunnel, "")
        filename = f"{prefix}{name}.conf"
        await query.message.reply_document(
            document=io.BytesIO(client_conf.encode()),
            filename=filename,
            caption=caption,
            parse_mode="Markdown",
        )

    elif data.startswith("confirmdel_"):
        name = data[11:]
        buttons = [
            [InlineKeyboardButton(f"\u2757 Да, удалить {name}", callback_data=f"delete_{name}")],
            [InlineKeyboardButton("\u2B05\uFE0F Отмена", callback_data=f"view_{name}")],
        ]
        await query.edit_message_text(
            f"\u26A0\uFE0F Удалить подключение *{name}*?\nЭто действие нельзя отменить.",
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="Markdown",
        )

    elif data.startswith("delete_"):
        name = data[7:]
        clients = load_clients()
        info = clients.get(name)
        if not info or (info.get("owner") != user_id and not is_admin(user_id)):
            await query.edit_message_text("Подключение не найдено.",
                                          reply_markup=main_menu_keyboard(user_id))
            return
        remove_peer_from_awg(info["pubkey"])
        del clients[name]
        save_clients(clients)

        user = query.from_user
        logger.info(
            f"DELETE CLIENT: {name} by @{user.username or '?'} "
            f"(id={user.id}, {_esc_md(user.first_name) or ''} {user.last_name or ''})"
        )

        await query.edit_message_text(
            f"\u2705 Подключение *{name}* удалено.",
            reply_markup=main_menu_keyboard(user_id),
            parse_mode="Markdown",
        )

    elif data == "server_status":
        try:
            # CPU / RAM
            load1 = os.getloadavg()[0]
            mem = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                parts = line.split()
                if parts[0].rstrip(":") in ("MemTotal", "MemAvailable"):
                    mem[parts[0].rstrip(":")] = int(parts[1]) * 1024
            ram_total = mem.get("MemTotal", 1)
            ram_used = ram_total - mem.get("MemAvailable", 0)
            ram_pct = ram_used / ram_total * 100

            # Disk
            st = os.statvfs("/")
            disk_total = st.f_blocks * st.f_frsize
            disk_free = st.f_bavail * st.f_frsize
            disk_pct = (1 - disk_free / disk_total) * 100

            # Peers
            awg_output = docker_exec("awg show awg0")
            total_peers = awg_output.count("peer:")
            online = 0
            for line in awg_output.splitlines():
                if "latest handshake" in line:
                    hs = line.split(":", 1)[1].strip()
                    if "second" in hs or "minute" in hs:
                        try:
                            parts = hs.replace(",", "").split()
                            secs = 0
                            for i, p in enumerate(parts):
                                if p in ("second", "seconds"):
                                    secs += int(parts[i-1])
                                elif p in ("minute", "minutes"):
                                    secs += int(parts[i-1]) * 60
                            if secs < 180:
                                online += 1
                        except (ValueError, IndexError):
                            pass

            # Top peers by traffic
            clients = load_clients()
            pk_to_name = {v["pubkey"]: k for k, v in clients.items()}
            peers_traffic = []
            current_pk = None
            for line in awg_output.splitlines():
                line = line.strip()
                if line.startswith("peer:"):
                    current_pk = line.split("peer:")[1].strip()
                elif "transfer:" in line and current_pk:
                    t = line.split(":", 1)[1].strip()
                    parts = t.split(",")
                    rx_str = parts[0].strip().split()
                    tx_str = parts[1].strip().split() if len(parts) > 1 else ["0", "B"]
                    def parse_size(val, unit):
                        mult = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
                        return float(val) * mult.get(unit, 1)
                    rx = parse_size(rx_str[0], rx_str[1]) if len(rx_str) >= 2 else 0
                    tx = parse_size(tx_str[0], tx_str[1]) if len(tx_str) >= 2 else 0
                    name = pk_to_name.get(current_pk, current_pk[:12])
                    peers_traffic.append((name, rx, tx))

            peers_traffic.sort(key=lambda x: x[1] + x[2], reverse=True)
            top5 = peers_traffic[:5]
            top_text = "\n".join(
                f"  {n}: \u2B07{human_bytes(rx)} \u2B06{human_bytes(tx)}"
                for n, rx, tx in top5
            ) or "  нет данных"

            # Uptime
            uptime_sec = float(Path("/proc/uptime").read_text().split()[0])
            days = int(uptime_sec // 86400)
            hours = int((uptime_sec % 86400) // 3600)

            text = (
                f"\U0001F4CA Статус сервера\n\n"
                f"\U0001F5A5 CPU: {load1:.1f} | RAM: {ram_pct:.0f}% ({human_bytes(ram_used)}/{human_bytes(ram_total)})\n"
                f"\U0001F4BE Диск: {disk_pct:.0f}% ({human_bytes(disk_total - disk_free)}/{human_bytes(disk_total)})\n"
                f"\u23F1 Аптайм: {days}д {hours}ч\n\n"
                f"\U0001F465 Пиры: {online} онлайн / {total_peers} всего\n\n"
                f"\U0001F4C8 Топ по трафику:\n{top_text}"
            )
        except Exception as e:
            text = f"\u274c Ошибка: {e}"

        buttons = [[InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")]]
        try:
            await query.edit_message_text(
                text,
                reply_markup=InlineKeyboardMarkup(buttons),
            )
        except Exception as e:
            logger.error(f"server_status edit failed: {e}")
            await query.edit_message_text(
                f"\u274c Ошибка отображения: {e}",
                reply_markup=main_menu_keyboard(user_id),
            )

    elif data == "support":
        await query.edit_message_text(
            "\u2709\uFE0F Напишите ваше сообщение для админа:"
        )
        return WAITING_MESSAGE

    elif data == "broadcast":
        if not is_admin(user_id):
            await query.edit_message_text("Нет доступа.", reply_markup=main_menu_keyboard(user_id))
            return
        # Submenu — choose audience
        buttons = [
            [InlineKeyboardButton("\U0001F9EA Тестовая (только мне)", callback_data="bcast_test")],
            [InlineKeyboardButton("\U0001F7E2 Только активным (7 дней)", callback_data="bcast_active")],
            [InlineKeyboardButton("\U0001F4E2 Всем", callback_data="bcast_all")],
            [InlineKeyboardButton("\u2B05\uFE0F Назад", callback_data="back_menu")],
        ]
        await query.edit_message_text(
            "\U0001F4E2 *Рассылка*\n\nКому отправить сообщение?",
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="Markdown",
        )
        return

    elif data in ("bcast_test", "bcast_active", "bcast_all"):
        if not is_admin(user_id):
            return
        audience = data[6:]  # 'test' / 'active' / 'all'
        context.user_data["broadcast_audience"] = audience
        labels = {"test": "тестовая (только мне)", "active": "активным за 7 дней", "all": "всем пользователям"}
        await query.edit_message_text(
            f"\U0001F4E2 *Рассылка: {labels[audience]}*\n\n"
            "Отправьте текст следующим сообщением. Поддерживается Markdown.\n"
            "Для отмены — /cancel",
            parse_mode="Markdown",
        )
        return WAITING_BROADCAST

    elif data.startswith("reply_"):
        target_id = int(data[6:])
        context.user_data["reply_to"] = target_id
        await query.edit_message_text(
            "\U0001F4DD Напишите ответ пользователю:"
        )
        return WAITING_REPLY

    elif data == "back_menu":
        user = query.from_user
        await query.edit_message_text(
            f"\U0001F510 *КВН*\n\nВыбери действие:",
            reply_markup=main_menu_keyboard(user_id),
            parse_mode="Markdown",
        )

    elif data.startswith("custom_toggle:"):
        # PR 2.5: flip a category in the custom-preset selection and redraw.
        cat = data.split(":", 1)[1]
        sel = set(context.user_data.get("custom_cats") or set())
        if cat in sel:
            sel.discard(cat)
        else:
            sel.add(cat)
        context.user_data["custom_cats"] = sel
        try:
            await query.edit_message_reply_markup(reply_markup=_render_custom_keyboard(sel))
        except Exception:
            # Telegram bails on identical markup — ignore.
            pass

    elif data == "custom_info":
        # Enter category drill-down screen.
        await query.edit_message_text(
            "*Что в каких категориях?*\n\nТапни категорию — увидишь список сервисов.",
            reply_markup=_render_info_categories_keyboard(),
            parse_mode="Markdown",
        )

    elif data.startswith("custom_info_cat:"):
        cat = data.split(":", 1)[1]
        svc_map = _load_services_by_category()
        services = svc_map.get(cat, [])
        emoji, name = CATEGORY_META.get(cat, ("·", cat))
        n4_map = {c: n4 for c, n4, _ in _load_categories_with_counts()}
        header = (
            f"*{emoji} {name}* — *{len(services)}* сервисов, "
            f"≈{n4_map.get(cat, 0)} IPv4 CIDR\n\n"
        )
        if services:
            body_lines = []
            for s in services:
                slug = s.get("slug", "")
                nm = s.get("name") or slug
                if nm and slug and nm.lower() != slug.lower():
                    body_lines.append(f"• {_esc_md(nm)} (`{_esc_md(slug)}`)")
                else:
                    body_lines.append(f"• `{_esc_md(slug)}`")
            body = "\n".join(body_lines)
        else:
            body = "_(список сервисов пока пуст)_"
        text = header + body
        if len(text) > 3800:
            text = text[:3800] + "\n\n…(обрезано — слишком много)"
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton("⬅️ Все категории", callback_data="custom_info"),
            InlineKeyboardButton("🎛 К выбору", callback_data="custom_info_back"),
        ]])
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=kb)

    elif data == "custom_info_back":
        sel = set(context.user_data.get("custom_cats") or set())
        await query.edit_message_text(
            "*Свой набор* — выбери нужные категории (можно несколько):",
            reply_markup=_render_custom_keyboard(sel),
            parse_mode="Markdown",
        )


async def cb_custom_done(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """PR 2.5: user finished picking custom categories. Transition into the
    peer-name WAITING_NAME state — this is registered as a ConversationHandler
    entry point."""
    q = update.callback_query
    await q.answer()
    sel = context.user_data.get("custom_cats") or set()
    if not sel:
        await q.answer("Выбери хотя бы одну категорию 🙏", show_alert=True)
        return
    user_id = q.from_user.id
    user_clients = get_user_clients(user_id)
    if not is_admin(user_id) and len(user_clients) >= MAX_CONNECTIONS:
        await q.edit_message_text(
            f"❌ У вас уже {MAX_CONNECTIONS} подключений (максимум).",
            reply_markup=main_menu_keyboard(user_id),
        )
        return ConversationHandler.END
    context.user_data["mode"] = "split"
    context.user_data["preset"] = "custom"
    context.user_data["custom_cats_list"] = sorted(sel)
    pretty = _category_pretty_list(sorted(sel))
    await q.edit_message_text(
        f"📝 *Свой набор*: _{pretty}_\n\nВведите имя подключения:",
        parse_mode="Markdown",
    )
    return WAITING_NAME


async def receive_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    user_clients = get_user_clients(user.id)

    if not is_admin(user.id) and len(user_clients) >= MAX_CONNECTIONS:
        await update.message.reply_text(
            f"\u274c У вас уже {MAX_CONNECTIONS} подключений (максимум).\n"
            "Удалите одно из существующих, чтобы создать новое.",
            reply_markup=main_menu_keyboard(user.id),
        )
        return ConversationHandler.END

    name = update.message.text.strip()

    if not name or " " in name or "/" in name:
        await update.message.reply_text(
            "\u274c Имя должно быть одним словом без пробелов. Попробуйте ещё:"
        )
        return WAITING_NAME

    clients = load_clients()
    if name in clients:
        await update.message.reply_text(
            f"\u274c Имя *{name}* уже занято. Введите другое:",
            parse_mode="Markdown",
        )
        return WAITING_NAME

    mode = context.user_data.pop("mode", "split")
    # backward-compat for any old paths still setting full_tunnel
    if context.user_data.pop("full_tunnel", False):
        mode = "full"
    kind = {"full": "чистый", "youtube": "YouTube", "split": "обычный"}[mode]

    msg = await update.message.reply_text(
        f"\u23f3 Создаю {kind} *{name}*...", parse_mode="Markdown"
    )

    privkey, pubkey = gen_keypair()
    psk = get_psk()
    client_ip = next_ip()

    add_peer_to_awg(pubkey, psk, client_ip)

    preset = context.user_data.pop("preset", None)
    custom_cats_list = context.user_data.pop("custom_cats_list", None)
    context.user_data.pop("custom_cats", None)  # cleanup intermediate set
    clients[name] = {
        "pubkey": pubkey,
        "privkey": privkey,
        "psk": psk,
        "ip": client_ip,
        "owner": user.id,
        "tunnel": mode,
    }
    if context.user_data.pop("rus_hop", False):
        clients[name]["rus_hop"] = True
    if preset:
        clients[name]["preset"] = preset
        if preset == "custom" and custom_cats_list:
            clients[name]["custom_categories"] = custom_cats_list
    save_clients(clients)

    _ep_override = RUS_HOP_ENDPOINT if clients[name].get("rus_hop") else None
    client_conf = generate_client_config(
        privkey, client_ip, psk, mode=mode, user_id=user.id,
        preset=preset, custom_categories=custom_cats_list,
        endpoint_override=_ep_override,
    )
    caption = build_caption(name, client_ip)
    if clients[name].get("rus_hop"):
        caption = "\U0001F1F7\U0001F1FA *\u0427\u0435\u0440\u0435\u0437 \u0420\u0424-\u0445\u043e\u043f* \u2014 \u0440\u043e\u0441\u0441\u0438\u0439\u0441\u043a\u0438\u0439 endpoint, \u0442\u0440\u0430\u0444\u0438\u043a \u0438\u0434\u0451\u0442 \u043d\u0430 \u0441\u0435\u0440\u0432\u0435\u0440 \u0447\u0435\u0440\u0435\u0437 relay.\n\n" + caption
    if mode == "full":
        caption = (
            f"\u26a0\ufe0f *Чистый конфиг* — весь трафик идёт через сервер.\n"
            f"YouTube/Instagram работают, но российские банки/госуслуги "
            f"могут блокировать вход (видят иностранный IP).\n\n"
        ) + caption
    elif mode == "youtube":
        caption = (
            f"\U0001F3AC *YouTube-конфиг* — через сервер идёт только Google/YouTube.\n"
            f"Всё остальное напрямую, можно держать включённым постоянно.\n\n"
        ) + caption
    prefix = {"full": "clean_", "youtube": "youtube_"}.get(mode, "")
    filename = f"{prefix}{name}.conf"

    await update.message.reply_document(
        document=io.BytesIO(client_conf.encode()),
        filename=filename,
        caption=caption,
        parse_mode="Markdown",
    )

    logger.info(
        f"NEW CLIENT ({kind}): {name} (ip={client_ip}) by @{user.username or '?'} "
        f"(id={user.id}, {_esc_md(user.first_name) or ''} {user.last_name or ''})"
    )

    await msg.delete()

    await update.message.reply_text(
        "\u2705 Готово!",
        reply_markup=main_menu_keyboard(user.id),
    )
    return ConversationHandler.END


async def cmd_support(update: Update, context: ContextTypes.DEFAULT_TYPE):
    save_user_meta(update.effective_user)
    # Admins can also use support — message goes to OTHER admins.
    await update.message.reply_text("\u2709\uFE0F Напишите ваше сообщение для админа:")
    return WAITING_MESSAGE


async def receive_support_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    text = update.message.text

    # Send to every support admin EXCEPT the sender (avoid self-loop for admins).
    recipients = [aid for aid in SUPPORT_IDS if aid != user.id]
    sent_count = 0
    failures = []

    for admin_id in recipients:
        try:
            keyboard = [[InlineKeyboardButton(
                "\U0001F4AC Ответить",
                callback_data=f"reply_{user.id}",
            )]]
            sender_role = "админа" if is_admin(user.id) else "пользователя"
            try:
                await context.bot.send_message(
                    chat_id=admin_id,
                    text=(
                        f"\u2709\uFE0F *Сообщение от {sender_role}*\n\n"
                        f"От: {user.first_name or ''} {user.last_name or ''} "
                        f"(@{user.username or '?'}, id: `{user.id}`)\n\n"
                        f"{text}"
                    ),
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="Markdown",
                )
            except Exception:
                # Markdown might break — retry as plain text
                await context.bot.send_message(
                    chat_id=admin_id,
                    text=(
                        f"✉️ Сообщение от {sender_role}\n\n"
                        f"От: {user.first_name or ''} {user.last_name or ''} "
                        f"(@{user.username or '?'}, id: {user.id})\n\n"
                        f"{text}"
                    ),
                    reply_markup=InlineKeyboardMarkup(keyboard),
                )
            sent_count += 1
            logger.info(f"Support msg from {user.id} delivered to admin {admin_id}")
        except Exception as e:
            failures.append((admin_id, str(e)))
            logger.error(f"Failed to send support msg to {admin_id}: {e}")

    if sent_count > 0:
        await update.message.reply_text(
            f"\u2705 Сообщение доставлено ({sent_count} получателей). Ожидайте ответа.",
            reply_markup=main_menu_keyboard(user.id),
        )
    else:
        err_text = ", ".join(f"{aid}: {err}" for aid, err in failures) if failures else "нет получателей"
        await update.message.reply_text(
            f"\u274c Не удалось доставить сообщение ни одному админу.\n{err_text}",
            reply_markup=main_menu_keyboard(user.id),
        )
    return ConversationHandler.END


async def receive_admin_reply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    save_user_meta(update.effective_user)
    target_id = context.user_data.get("reply_to")
    if not target_id:
        await update.message.reply_text("Ошибка: не найден получатель.")
        return ConversationHandler.END

    text = update.message.text
    try:
        await context.bot.send_message(
            chat_id=target_id,
            text=f"\U0001F4AC *Ответ от админа*\n\n{text}",
            parse_mode="Markdown",
        )
        await update.message.reply_text("\u2705 Ответ отправлен.")
    except Exception as e:
        await update.message.reply_text(f"\u274c Не удалось отправить: {e}")

    context.user_data.pop("reply_to", None)
    return ConversationHandler.END


async def receive_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin sent the broadcast text — fan it out to selected audience."""
    user = update.effective_user
    save_user_meta(user)
    if not is_admin(user.id):
        return ConversationHandler.END

    text = update.message.text or ""
    audience = context.user_data.pop("broadcast_audience", "all")

    if audience == "test":
        targets = [user.id]
    else:
        seen = load_seen_users()
        if audience == "active":
            # Filter to users who have any peer with handshake < 7 days
            try:
                dump = docker_exec("awg show awg0 dump")
                now_ts = time.time()
                active_pks = set()
                for line in dump.splitlines()[1:]:
                    cols = line.split("\t")
                    if len(cols) >= 7 and cols[4].isdigit():
                        if now_ts - int(cols[4]) < 7 * 86400:
                            active_pks.add(cols[0])
            except Exception:
                active_pks = set()

            clients = load_clients()
            active_owners = set()
            for name, info in clients.items():
                if info.get("pubkey") in active_pks:
                    owner = info.get("owner")
                    if isinstance(owner, int):
                        active_owners.add(owner)
            targets = sorted(active_owners & seen)
        else:
            targets = sorted(seen)

    total = len(targets)
    audience_label = {"test": "тестовая (только мне)", "active": "активным", "all": "всем"}[audience]
    await update.message.reply_text(f"\U0001F4E2 Начинаю рассылку ({audience_label}) для {total} пользователей...")

    sent = 0
    blocked = 0
    failed = 0
    for tg_id in targets:
        try:
            await context.bot.send_message(
                chat_id=tg_id,
                text=text,
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
            sent += 1
        except Exception as e:
            err = str(e).lower()
            if "blocked" in err or "deactivated" in err or "chat not found" in err:
                blocked += 1
            else:
                failed += 1
            logger.warning(f"broadcast to {tg_id} failed: {e}")
        # stay well under Telegram's ~30 msg/sec global limit
        import asyncio
        await asyncio.sleep(0.05)

    report = (
        f"\U0001F4E2 *Рассылка завершена*\n\n"
        f"Всего: {total}\n"
        f"\u2705 Доставлено: {sent}\n"
        f"\U0001F6AB Заблокировали бота: {blocked}\n"
        f"\u274c Ошибок: {failed}"
    )
    try:
        await update.message.reply_text(report, parse_mode="Markdown",
                                        reply_markup=main_menu_keyboard(user.id))
    except Exception:
        await update.message.reply_text(report.replace("*", ""),
                                        reply_markup=main_menu_keyboard(user.id))
    logger.info(f"BROADCAST by {user.id}: total={total} sent={sent} blocked={blocked} failed={failed}")
    return ConversationHandler.END


async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user_meta(user)
    if not is_admin(user.id):
        await update.message.reply_text("Команда доступна только админам.")
        return ConversationHandler.END
    await update.message.reply_text(
        "\U0001F4E2 *Рассылка всем пользователям*\n\n"
        "Отправьте текст следующим сообщением. Поддерживается Markdown.\n"
        "Для отмены — /cancel",
        parse_mode="Markdown",
    )
    return WAITING_BROADCAST


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if update.message:
        await update.message.reply_text(
            "Отменено.",
            reply_markup=main_menu_keyboard(user.id),
        )
    return ConversationHandler.END


async def conv_timeout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # state протух — сообщить юзеру и закрыть conversation
    chat_id = update.effective_chat.id if update.effective_chat else None
    if chat_id:
        try:
            await context.bot.send_message(chat_id, "⏱ Сессия истекла. Начни заново — /start или нужная команда.")
        except Exception:
            pass
    return ConversationHandler.END


# --- Web user cleanup job ---

async def cleanup_unverified(context: ContextTypes.DEFAULT_TYPE):
    web_users = load_json(WEB_USERS_FILE)
    if not web_users:
        return

    clients = load_clients()
    banned = load_json(BASE_DIR / "banned.json")
    now = time.time()
    changed_users = False
    changed_clients = False

    # Get all real bot user IDs to protect them
    real_bot_users = set()
    seen = load_seen_users()
    real_bot_users.update(seen)
    for info in clients.values():
        owner = info.get("owner")
        if isinstance(owner, int):
            real_bot_users.add(owner)

    for username in list(web_users.keys()):
        udata = web_users[username]
        if udata.get("verified"):
            continue

        created = udata.get("created", "")
        try:
            from datetime import datetime
            created_ts = datetime.fromisoformat(created).timestamp()
        except (ValueError, TypeError):
            continue

        if now - created_ts < 1800:  # 30 min
            continue

        # Check if username matches a real bot user — don't touch their connections
        is_real_user = False
        for uid in real_bot_users:
            # We can't check username→uid mapping here easily, so just skip deletion
            # of connections if they belong to a real integer owner
            pass

        # Delete web connections
        prefix = f"w_{username}_"
        for conn_name in list(clients.keys()):
            if conn_name.startswith(prefix):
                info = clients[conn_name]
                owner = info.get("owner")
                # Only delete if owner is web-based, not a real tg user
                if isinstance(owner, str) and owner == f"w_{username}":
                    try:
                        remove_peer_from_awg(info["pubkey"])
                    except Exception:
                        pass
                    del clients[conn_name]
                    changed_clients = True
                    logger.info(f"CLEANUP: removed web connection {conn_name}")

        # Increment strikes
        udata["strikes"] = udata.get("strikes", 0) + 1
        if udata["strikes"] >= 2:
            banned[username] = {
                "reason": "2 strikes - unverified timeout",
                "banned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            del web_users[username]
            logger.info(f"CLEANUP: banned web user {username} (2 strikes)")
        else:
            # Reset created time so they get another 30 min if they log in again
            pass

        changed_users = True

    if changed_users:
        save_json(WEB_USERS_FILE, web_users)
        save_json(BASE_DIR / "banned.json", banned)
    if changed_clients:
        save_clients(clients)


def main():
    install_bridge()  # tg_html: Markdown→HTML auto-bridge
    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(button_handler, pattern="^new_client$"),
            CallbackQueryHandler(button_handler, pattern="^new_(split|clean|rus)$"),
            CallbackQueryHandler(button_handler, pattern="^support$"),
            CallbackQueryHandler(button_handler, pattern="^bcast_(test|active|all)$"),
            CallbackQueryHandler(button_handler, pattern="^reply_"),
            CallbackQueryHandler(cb_admindom_add, pattern="^admindom_add$"),
            CallbackQueryHandler(cb_mydom_add, pattern="^mydom_add(?::\\w+)?$"),
            CallbackQueryHandler(button_handler, pattern="^new_pro$"),
            CallbackQueryHandler(button_handler, pattern="^new_preset_"),
            CallbackQueryHandler(cb_custom_done, pattern="^custom_done$"),
            CommandHandler("new", cmd_new),
            CommandHandler("support", cmd_support),
            CommandHandler("broadcast", cmd_broadcast),
        ],
        states={
            WAITING_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_name)],
            WAITING_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_support_message)],
            WAITING_REPLY: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_admin_reply)],
            WAITING_BROADCAST: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_broadcast)],
            WAITING_ADMIN_DOMAIN: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_admin_domain),
                CallbackQueryHandler(cb_admindom_cancel_in_state, pattern="^admindom_cancel$"),
            ],
            WAITING_MY_DOMAIN: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_my_domain),
                CallbackQueryHandler(cb_mydom_cancel_in_state, pattern="^mydom_cancel$"),
            ],
            ConversationHandler.TIMEOUT: [MessageHandler(filters.ALL, conv_timeout)],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            # любая /команда сбрасывает зависший state (раньше без этого юзер мог застрять
            # после неоконченного /new/support/etc и любое следующее сообщение трактовалось
            # как ответ на тот старый запрос)
            MessageHandler(filters.COMMAND, cancel),
        ],
        # allow_reentry=True: если пользователь застрял в каком-то WAITING_*
        # state (например начал /new, не ввёл имя и ушёл), новый entry_point
        # callback (🎛 Pro-режим → выбор категорий → Создать, или любая другая
        # кнопка которая хочет открыть conversation) перезапишет state вместо
        # тихого игнорирования. Без этого вся схема dead-lock'ится.
        allow_reentry=True,
        # Состояние самоочищается через 5 минут бездействия — иначе старый WAITING_*
        # переживает на дни и ломает любые следующие сообщения юзера.
        conversation_timeout=300,
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("clients", cmd_clients))
    app.add_handler(CommandHandler("invite", cmd_invite))
    app.add_handler(CallbackQueryHandler(cb_invite_create, pattern="^invite_create$"))
    app.add_handler(CallbackQueryHandler(cb_invite_open, pattern="^invite_open$"))
    app.add_handler(CallbackQueryHandler(cb_invite_open_uses, pattern=r"^invite_open_uses:"))
    app.add_handler(CallbackQueryHandler(cb_invite_open_make, pattern=r"^invite_open_make:"))
    app.add_handler(CallbackQueryHandler(cb_invite_open_list, pattern="^invite_open_list$"))
    app.add_handler(CallbackQueryHandler(cb_invite_open_revoke, pattern=r"^invite_open_revoke:"))
    app.add_handler(CallbackQueryHandler(cb_clients_view, pattern="^clients_view$"))
    app.add_handler(CallbackQueryHandler(cb_bcast_send, pattern="^bcast_send:"))
    app.add_handler(CallbackQueryHandler(cb_bcast_cancel, pattern="^bcast_cancel:"))
    app.add_handler(CommandHandler("my", cmd_my))
    app.add_handler(CommandHandler("verify", cmd_verify))
    # Stage 2 fix: diff alert button handlers
    app.add_handler(CallbackQueryHandler(cb_diff_broadcast, pattern="^diff_broadcast:"))
    app.add_handler(CallbackQueryHandler(cb_diff_skip, pattern="^diff_skip:"))
    # Stage 3: admin_domains
    app.add_handler(CommandHandler("admin_domains", cmd_admin_domains))
    app.add_handler(CallbackQueryHandler(cb_admindom_menu, pattern="^admindom_menu$"))
    app.add_handler(CallbackQueryHandler(cb_admindom_remove, pattern="^admindom_remove$"))
    app.add_handler(CallbackQueryHandler(cb_admindom_del, pattern="^admindom_del:"))
    # PR 1: per-user /my_domains + promoter
    app.add_handler(CommandHandler("subscription", cmd_subscription))
    app.add_handler(CallbackQueryHandler(cb_subscription_menu, pattern="^subscription_menu$"))
    app.add_handler(CallbackQueryHandler(cb_subscription_create, pattern="^subscription_create$"))
    app.add_handler(CallbackQueryHandler(cb_subscription_rotate, pattern="^subscription_rotate$"))
    app.add_handler(CommandHandler("my_domains", cmd_my_domains))
    app.add_handler(CallbackQueryHandler(cb_mydom_menu, pattern="^mydom_menu$"))
    app.add_handler(CallbackQueryHandler(cb_mydom_remove, pattern="^mydom_remove$"))
    app.add_handler(CallbackQueryHandler(cb_mydom_del, pattern="^mydom_del:"))
    app.add_handler(CallbackQueryHandler(cb_promote_domain, pattern="^promote_domain:"))
    app.add_handler(CallbackQueryHandler(cb_promote_skip, pattern="^promote_skip:"))
    app.add_handler(conv_handler)
    app.add_handler(CallbackQueryHandler(button_handler))

    # Cleanup job every 5 minutes
    app.job_queue.run_repeating(cleanup_unverified, interval=300, first=60)

    # Re-enroll HAPP subscription clients into xray (runtime-only state lost on container restart)
    try:
        sync_xray_clients_from_meta()
    except Exception as _e:
        logger.warning(f"xray_sync on startup failed: {_e!r}")

    logger.info("Bot started")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
