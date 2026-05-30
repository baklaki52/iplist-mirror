#!/usr/bin/env python3
import json
import invites
import os
import subprocess
import logging
import re
import time
import tempfile
from datetime import datetime
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Updater, CommandHandler, CallbackQueryHandler, CallbackContext, MessageHandler, Filters
)

# XRay helper (VLESS+Reality via amnezia-xray container)
import xray_helper

# Per-user custom domains (/my_domains feature)
import user_domains as ud
from tg_html import install_bridge

# Load .env
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(Path(__file__).parent / "bot.log"),
    ]
)
logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────
BOT_TOKEN = os.environ["BOT_TOKEN"]  # must be set in .env or environment
ADMIN_IDS = {211890697}              # видят всё, без лимита, удаляют любые
CLIENTS_VIEW_IDS = {211890697}  # /clients access
SUPPORT_IDS = {211890697}            # получают сообщения от юзеров
CONTAINER = "amnezia-awg2"
AWG_CONF = "/opt/amnezia/awg/awg0.conf"
CLIENTS_TABLE = "/opt/amnezia/awg/clientsTable"
SERVER_PUBLIC_KEY_FILE = "/opt/amnezia/awg/wireguard_server_public_key.key"
PSK_FILE = "/opt/amnezia/awg/wireguard_psk.key"
DB_FILE = Path(__file__).parent / "users_db.json"
USER_DOMAINS_FILE = Path(__file__).parent / "user_domains.json"
MAX_DOMAINS_PER_USER = 10
ADMIN_DOMAINS_FILE = Path(__file__).parent / "admin_domains.json"
FETCH_LISTS_SCRIPT = Path(__file__).parent / "fetch_lists.py"
CHAT_LOG_FILE = Path(__file__).parent / "chat_log.jsonl"
MAX_CONNECTIONS = 3
SERVER_IP = "185.171.80.233"
SERVER_PORT = "41901"
SUBNET = "10.8.1"
DNS = "172.29.172.254"
ALLOWED_IPS_FILE = Path(__file__).parent / "allowed_ips.json"
ALLOWED_IPS_V6_FILE = Path(__file__).parent / "allowed_ips_v6.json"
ALLOWED_IPS_YT_FILE = Path(__file__).parent / "allowed_ips_youtube.json"
V6_PREFIX = "fd42:42:42::"  # ULA inside the tunnel; one /128 per client

AWG_PARAMS = {
    "Jc": "5", "Jmin": "10", "Jmax": "50",
    "S1": "63", "S2": "34", "S3": "39", "S4": "7",
    "H1": "1676119367-1723227551",
    "H2": "1955271282-2028122572",
    "H3": "2102428174-2111211147",
    "H4": "2122287007-2129172232",
}

# ── State ───────────────────────────────────────────────────────────────
AWAITING_NAME = set()         # user_ids waiting to type connection name
AWAITING_SUPPORT = set()      # user_ids waiting to type support message
AWAITING_REPLY = {}           # admin_id → target_user_id
AWAITING_BROADCAST = set()    # admin_ids composing a broadcast message
BROADCAST_AUDIENCE = {}       # admin_id → 'test' | 'active' | 'all'
AWAITING_MY_DOMAIN = set()    # user_ids waiting to type domain for /my_domains
AWAITING_ADMIN_DOMAIN = set() # admin_ids waiting to type domain for /admin_domains


# ── Helpers ─────────────────────────────────────────────────────────────


def _esc_md(s):
    """Escape Markdown special chars in user-supplied text."""
    if not s: return ""
    for ch in ("\\", "`", "*", "_", "[", "]", "(", ")", "~", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
        s = s.replace(ch, "\\" + ch)
    return s

def is_admin(user_id):
    return user_id in ADMIN_IDS


def tg_user_label(user):
    parts = [p for p in [user.first_name, user.last_name] if p]
    name = " ".join(parts) or "?"
    if user.username:
        return f"@{user.username} ({name}, id:{user.id})"
    return f"{name} (id:{user.id})"


def chat_log(user, action, details=""):
    entry = {
        "ts": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user.id,
        "username": user.username or "",
        "first_name": user.first_name or "",
        "last_name": user.last_name or "",
        "action": action,
        "details": details,
    }
    with open(CHAT_LOG_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.info(f"@{entry['username'] or entry['first_name']}({entry['user_id']}) {action} {details}")


def load_allowed_ips():
    with open(ALLOWED_IPS_FILE, "r") as f:
        data = json.load(f)
    if isinstance(data, list) and data:
        if isinstance(data[0], str):
            return data
        return [r["hostname"].replace("\\/", "/") for r in data]
    return []


def load_allowed_ips_v6():
    if not ALLOWED_IPS_V6_FILE.exists():
        return []
    with open(ALLOWED_IPS_V6_FILE, "r") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def load_allowed_ips_youtube():
    if not ALLOWED_IPS_YT_FILE.exists():
        return []
    with open(ALLOWED_IPS_YT_FILE, "r") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def client_v6(client_ip):
    """Map IPv4 client address (e.g. 10.8.1.5) to its tunnel IPv6 (fd42:42:42::5)."""
    last = client_ip.rstrip("/").split(".")[-1]
    return f"{V6_PREFIX}{last}"


def load_db():
    if DB_FILE.exists():
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def save_user_info(db, user):
    if "_users" not in db:
        db["_users"] = {}
    db["_users"][str(user.id)] = {
        "user_id": user.id,
        "username": user.username or "",
        "first_name": user.first_name or "",
        "last_name": user.last_name or "",
        "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }


def find_conn_owner(db, ident):
    """Find which user_id owns this connection.
    `ident` can be a pubkey (AWG) or a uuid (XRay).
    Returns (uid_str, conn_dict) or (None, None)."""
    for uid, conns in db.items():
        if uid.startswith("_"):
            continue
        if isinstance(conns, list):
            for c in conns:
                if c.get("pubkey") == ident or c.get("uuid") == ident:
                    return uid, c
    return None, None


def conn_key(conn):
    """Return the stable identifier for a connection (pubkey for AWG, uuid for XRay)."""
    return conn.get("uuid") or conn.get("pubkey")


def conn_type(conn):
    """Return connection type: 'xray' or 'awg' (default)."""
    return conn.get("type", "awg")


# ── Docker / AWG ────────────────────────────────────────────────────────

def docker_exec(cmd, input_data=None):
    full_cmd = ["docker", "exec"]
    if input_data:
        full_cmd.append("-i")
    full_cmd.extend([CONTAINER] + cmd)
    result = subprocess.run(full_cmd, capture_output=True, text=True, input=input_data)
    if result.returncode != 0:
        logger.error(f"docker exec error: {result.stderr}")
    return result.stdout.strip()


def get_server_public_key():
    return docker_exec(["cat", SERVER_PUBLIC_KEY_FILE])


def get_psk():
    return docker_exec(["cat", PSK_FILE])


def gen_keypair():
    privkey = docker_exec(["awg", "genkey"])
    pubkey = docker_exec(["awg", "pubkey"], input_data=privkey)
    return privkey, pubkey


def get_used_ips():
    conf = docker_exec(["cat", AWG_CONF])
    ips = set()
    for line in conf.splitlines():
        line = line.strip()
        if line.startswith("AllowedIPs"):
            ip = line.split("=")[1].strip().split("/")[0]
            ips.add(ip)
    ips.add(f"{SUBNET}.0")
    return ips


def next_free_ip():
    used = get_used_ips()
    for i in range(2, 255):
        ip = f"{SUBNET}.{i}"
        if ip not in used:
            return ip
    return None


def add_peer_to_config(pubkey, psk, client_ip):
    # Read current config, strip trailing whitespace, append peer with
    # proper blank-line separator. Always write the whole file via stdin
    # so we guarantee correct newlines (append can glue content if the
    # file ends without a newline).
    conf = docker_exec(["cat", AWG_CONF]).rstrip()
    v6 = client_v6(client_ip)
    peer_block = (
        f"[Peer]\n"
        f"PublicKey = {pubkey}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_ip}/32, {v6}/128\n"
    )
    new_conf = conf + "\n\n" + peer_block
    docker_exec(["sh", "-c", f"cat > {AWG_CONF}"], input_data=new_conf)
    docker_exec(["sh", "-c", f"awg syncconf awg0 <(awg-quick strip {AWG_CONF})"])


def remove_peer_from_config(pubkey):
    docker_exec(["awg", "set", "awg0", "peer", pubkey, "remove"])
    conf = docker_exec(["cat", AWG_CONF])
    # Parse line-by-line: keep all [Peer] blocks except the one whose
    # PublicKey matches. This is safer than regex because it guarantees
    # correct blank-line separators between blocks.
    lines = conf.splitlines()
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == "[Peer]":
            # Collect this peer block
            block = [line]
            j = i + 1
            while j < len(lines) and lines[j].strip() != "[Peer]":
                block.append(lines[j])
                j += 1
            # Check if this block contains our target pubkey
            block_text = "\n".join(block)
            if f"PublicKey = {pubkey}" in block_text or f"PublicKey={pubkey}" in block_text:
                # Drop this block
                pass
            else:
                result.extend(block)
            i = j
        else:
            result.append(line)
            i += 1

    new_conf = "\n".join(result).rstrip() + "\n"
    docker_exec(["sh", "-c", f"cat > {AWG_CONF}"], input_data=new_conf)
    docker_exec(["sh", "-c", f"awg syncconf awg0 <(awg-quick strip {AWG_CONF})"])


def update_clients_table(pubkey, client_name, remove=False):
    raw = docker_exec(["cat", CLIENTS_TABLE])
    try:
        clients = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        clients = []
    if remove:
        clients = [c for c in clients if c.get("clientId") != pubkey]
    else:
        clients.append({
            "clientId": pubkey,
            "userData": {"clientName": client_name, "creationDate": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
        })
    data = json.dumps(clients, indent=4)
    docker_exec(["sh", "-c", f"cat > {CLIENTS_TABLE} << 'CTEOF'\n{data}\nCTEOF"])


def _load_ordered_ips():
    """allowed_ips_ordered.json — per-service popularity-ranked array."""
    import os
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowed_ips_ordered.json")
        with open(p) as f:
            d = json.load(f)
            return d if isinstance(d, list) else []
    except Exception:
        return []


def _load_priority_ips():
    """Load allowed_ips_priority.json → {"v4":[...], "v6":[...]}; empty if missing.

    Legacy format. New consumers should prefer _load_priority_flat() which
    returns a per-service v4+v6 adjacent flat list."""
    import os
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowed_ips_priority.json")
        with open(p) as f:
            d = json.load(f)
            return {"v4": d.get("v4", []), "v6": d.get("v6", [])}
    except Exception:
        return {"v4": [], "v6": []}


def _load_priority_flat():
    """Load allowed_ips_priority_flat.json — single flat list with v4+v6 of
    each priority service adjacent (the iOS NE / AWG-safe order).
    Returns [] if missing — caller falls back to _load_priority_ips()."""
    import os
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowed_ips_priority_flat.json")
        with open(p) as f:
            d = json.load(f)
            return d if isinstance(d, list) else []
    except Exception:
        return []


def generate_client_config(privkey, client_ip, psk, mode="split", user_id=None):
    """Generate AmneziaWG client config.

    mode="split"   — default split tunneling via allowed_ips.json + v6.
    mode="full"    — route ALL traffic through the VPN (0.0.0.0/0, ::/0).
    mode="youtube" — only Google/YouTube CIDRs + forced DNS through our server.

    user_id: Telegram ID of the config owner. When set AND mode=="split",
    the user's /my_domains entries (user_domains.json) are appended to AllowedIPs.
    """
    server_pubkey = get_server_public_key()
    if mode == "full":
        allowed_ips_str = "0.0.0.0/0, ::/0"
    elif mode == "youtube":
        yt = load_allowed_ips_youtube()
        parts = ["172.29.172.254/32"] + yt
        allowed_ips_str = ", ".join(parts)
    else:
        _ord = _load_ordered_ips()
        if _ord:
            _base = _ord                         # per-service popularity-ranked
        else:
            _base = load_allowed_ips() + load_allowed_ips_v6()  # fallback flat
        # PRIORITY HEAD — critical services pinned to the front (hard guarantee),
        # ordered list provides the ranked rest. v4+v6 per-service adjacent.
        # Prefer the new flat file (per-group adjacency); fall back to the
        # legacy dict format if it's not generated yet.
        _pri_flat = _load_priority_flat()
        if _pri_flat:
            _head = ["172.29.172.254/32"] + _pri_flat
        else:
            _pri = _load_priority_ips()
            _head = ["172.29.172.254/32"] + _pri["v4"] + _pri["v6"]
        _raw = _head + _base
        _seen = set()
        parts = []
        for _c in _raw:
            _c = _c.strip()
            if _c and _c not in _seen:
                _seen.add(_c)
                parts.append(_c)
        # PR: per-user custom domains (/my_domains) — split-mode only
        if user_id is not None:
            u_v4, u_v6 = ud.collect_ips(USER_DOMAINS_FILE, str(user_id))
            parts += [f"{ip}/32" for ip in u_v4]
            parts += [f"{ip}/128" for ip in u_v6]
        allowed_ips_str = ", ".join(parts)

    return f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/32
DNS = {DNS}
Jc = {AWG_PARAMS['Jc']}
Jmin = {AWG_PARAMS['Jmin']}
Jmax = {AWG_PARAMS['Jmax']}
S1 = {AWG_PARAMS['S1']}
S2 = {AWG_PARAMS['S2']}
S3 = {AWG_PARAMS['S3']}
S4 = {AWG_PARAMS['S4']}
H1 = {AWG_PARAMS['H1']}
H2 = {AWG_PARAMS['H2']}
H3 = {AWG_PARAMS['H3']}
H4 = {AWG_PARAMS['H4']}

[Peer]
PublicKey = {server_pubkey}
PresharedKey = {psk}
AllowedIPs = {allowed_ips_str}
Endpoint = {SERVER_IP}:{SERVER_PORT}
PersistentKeepalive = 25
"""


INSTRUCTION_TEXT = (
    "📥 *Скачать приложение:*\n"
    "📱 Android — [AmneziaVPN (Google Play)](https://play.google.com/store/apps/details?id=org.amnezia.vpn)\n"
    "🍏 iPhone (иностр. App Store) — [AmneziaVPN](https://apps.apple.com/app/amneziavpn/id1600529900)\n"
    "🍏 iPhone (рос. App Store) — [AmneziaWG](https://apps.apple.com/ru/app/amneziawg/id6478942365)\n\n"
    "*Как подключиться:*\n"
    "1. Нажмите на файл выше\n"
    "2. «Поделиться» → ещё раз «Поделиться» → выберите приложение Amnezia\n"
    "3. Дайте приложению все разрешения\n\n"
    "Можно не выключать — идёт только нужный трафик, "
    "на скорость и батарею не влияет."
)

INSTRUCTION_TEXT_CLEAN = (
    "📥 *Скачать приложение:*\n"
    "📱 Android — [AmneziaVPN (Google Play)](https://play.google.com/store/apps/details?id=org.amnezia.vpn)\n"
    "🍏 iPhone (иностр. App Store) — [AmneziaVPN](https://apps.apple.com/app/amneziavpn/id1600529900)\n"
    "🍏 iPhone (рос. App Store) — [AmneziaWG](https://apps.apple.com/ru/app/amneziawg/id6478942365)\n\n"
    "*Как подключиться:*\n"
    "1. Нажмите на файл выше\n"
    "2. «Поделиться» → ещё раз «Поделиться» → выберите приложение Amnezia\n"
    "3. Дайте приложению все разрешения"
)


# ── Business logic ──────────────────────────────────────────────────────

def create_connection(user, conn_name, mode="split"):
    """Create an AmneziaWG connection. Returns (config_str, error).

    mode = "split" | "full" | "youtube"
    """
    full_tunnel = (mode == "full")
    db = load_db()
    uid = str(user.id)
    save_user_info(db, user)
    user_conns = db.get(uid, [])

    if not is_admin(user.id) and len(user_conns) >= MAX_CONNECTIONS:
        return None, f"Достигнут лимит ({MAX_CONNECTIONS} подключений)."

    # Check unique name for this user
    if any(c["name"] == conn_name for c in user_conns):
        return None, f"Подключение «{conn_name}» уже существует."

    client_ip = next_free_ip()
    if not client_ip:
        return None, "Нет свободных IP-адресов."

    privkey, pubkey = gen_keypair()
    psk = get_psk()

    add_peer_to_config(pubkey, psk, client_ip)
    table_prefix = {"full": "tgfull", "youtube": "tgyt", "split": "tg"}.get(mode, "tg")
    update_clients_table(pubkey, f"{table_prefix}_{user.id}_{conn_name}")

    config = generate_client_config(privkey, client_ip, psk, mode=mode, user_id=user.id)

    user_conns.append({
        "name": conn_name,
        "type": "awg",
        "tunnel": mode,
        "pubkey": pubkey,
        "privkey": privkey,
        "psk": psk,
        "ip": client_ip,
        "created": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    })
    db[uid] = user_conns
    save_db(db)

    kind = {"full": "AWG-FULL", "youtube": "AWG-YT", "split": "AWG"}.get(mode, "AWG")
    logger.info(f"NEW {kind} CLIENT: {conn_name} (ip={client_ip}) by {tg_user_label(user)}")
    chat_log(user, "create_connection", f"type=awg tunnel={mode} name={conn_name} ip={client_ip}")
    return config, None


def create_xray_connection(user, conn_name):
    """Create an XRay (VLESS+Reality) connection. Returns (json_file, uuid, error).
    Only generates plain XRay JSON (for Happ, v2rayNG, V2Box) — Amnezia .vpn
    wrapper is not supported because Amnezia ignores routing.rules for XRay
    containers and requires split tunneling configured via its UI."""
    db = load_db()
    uid = str(user.id)
    save_user_info(db, user)
    user_conns = db.get(uid, [])

    if not is_admin(user.id) and len(user_conns) >= MAX_CONNECTIONS:
        return None, None, f"Достигнут лимит ({MAX_CONNECTIONS} подключений)."

    if any(c["name"] == conn_name for c in user_conns):
        return None, None, f"Подключение «{conn_name}» уже существует."

    try:
        import uuid as _uuid_mod
        client_uuid = str(_uuid_mod.uuid4())
        xray_helper.xray_add_client(client_uuid)
        xray_helper.xray_update_clients_table(client_uuid, f"tg_{user.id}_{conn_name}")
        json_file = xray_helper.build_plain_xray_json(client_uuid)
    except Exception as e:
        logger.error(f"xray create failed: {e}")
        return None, None, f"Ошибка XRay: {e}"

    user_conns.append({
        "name": conn_name,
        "type": "xray",
        "uuid": client_uuid,
        "created": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    })
    db[uid] = user_conns
    save_db(db)

    logger.info(f"NEW XRAY CLIENT: {conn_name} (uuid={client_uuid}) by {tg_user_label(user)}")
    chat_log(user, "create_connection", f"type=xray name={conn_name} uuid={client_uuid}")
    return json_file, client_uuid, None


def delete_connection_by_pubkey(actor, ident):
    """Delete connection by pubkey (AWG) or uuid (XRay).
    Actor may be admin deleting someone else's connection."""
    db = load_db()
    owner_uid, conn = find_conn_owner(db, ident)
    if not conn:
        return "Подключение не найдено."

    # Permission check: owner or admin
    if str(actor.id) != owner_uid and not is_admin(actor.id):
        return "Нет прав для удаления."

    ctype = conn_type(conn)
    if ctype == "xray":
        try:
            xray_helper.delete_xray_connection(conn["uuid"])
        except Exception as e:
            logger.error(f"xray delete failed: {e}")
    else:  # awg
        remove_peer_from_config(conn["pubkey"])
        update_clients_table(conn["pubkey"], "", remove=True)

    key = conn_key(conn)
    db[owner_uid] = [c for c in db.get(owner_uid, []) if conn_key(c) != key]
    save_db(db)

    logger.info(f"DELETE {ctype.upper()} CLIENT: {conn['name']} by {tg_user_label(actor)}")
    chat_log(actor, "delete_connection", f"type={ctype} name={conn['name']}")
    return None


# ── Server stats (for admin) ───────────────────────────────────────────

def get_server_stats():
    """Collect server health stats for admin dashboard."""
    # System
    load1, load5, load15 = os.getloadavg()
    with open("/proc/meminfo") as f:
        mem = {}
        for line in f:
            parts = line.split()
            if parts[0] in ("MemTotal:", "MemAvailable:"):
                mem[parts[0]] = int(parts[1])
    total_mb = mem.get("MemTotal:", 0) // 1024
    avail_mb = mem.get("MemAvailable:", 0) // 1024
    used_mb = total_mb - avail_mb

    # Disk
    st = os.statvfs("/")
    disk_total_gb = round(st.f_blocks * st.f_frsize / 1e9, 1)
    disk_free_gb = round(st.f_bavail * st.f_frsize / 1e9, 1)

    # Collect peers from all services
    def _wg_peers(container, cmd):
        try:
            out = subprocess.run(
                ["docker", "exec", container] + cmd,
                capture_output=True, text=True, timeout=5
            ).stdout.strip()
            lines = out.strip().split("\n")[1:] if out else []
            peers = []
            now = time.time()
            for line in lines:
                cols = line.split("\t")
                if len(cols) >= 7:
                    pubkey = cols[0]
                    last_hs = int(cols[4]) if cols[4].isdigit() else 0
                    rx, tx = int(cols[5]), int(cols[6])
                    ip = cols[3].split("/")[0]
                    is_active = last_hs > 0 and (now - last_hs) < 180
                    peers.append({"ip": ip, "rx": rx, "tx": tx, "active": is_active, "pubkey": pubkey})
            return peers
        except Exception:
            return []

    def _wge_names():
        """Load name→pubkey map from WG-Easy's wg0.json."""
        try:
            out = subprocess.run(
                ["docker", "exec", "amnezia-wg-easy", "cat", "/etc/wireguard/wg0.json"],
                capture_output=True, text=True, timeout=5
            ).stdout
            data = json.loads(out)
            names = {}
            for cid, c in data.get("clients", {}).items():
                pk = c.get("publicKey", "")
                if pk:
                    names[pk] = c.get("name", "")
            return names
        except Exception:
            return {}

    def _xui_clients():
        try:
            import sqlite3
            conn = sqlite3.connect("/etc/x-ui/x-ui.db")
            rows = conn.execute("SELECT email, up, down, enable FROM client_traffics WHERE enable=1").fetchall()
            conn.close()
            return rows
        except Exception:
            return []

    awg_peers = _wg_peers(CONTAINER, ["awg", "show", "awg0", "dump"])
    wge_peers = _wg_peers("amnezia-wg-easy", ["wg", "show", "wg0", "dump"])
    wge_names = _wge_names()
    xui_clients = _xui_clients()

    all_wg_peers = awg_peers + wge_peers
    total_peers = len(all_wg_peers) + len(xui_clients)
    active_peers = sum(1 for p in all_wg_peers if p["active"])

    # Network speed (read /proc/net/dev twice with 1s gap)
    def read_eth0():
        with open("/proc/net/dev") as f:
            for l in f:
                if "eth0:" in l:
                    p = l.split()
                    return int(p[1]), int(p[9])
        return 0, 0

    rx1, tx1 = read_eth0()
    time.sleep(1)
    rx2, tx2 = read_eth0()
    rx_mbps = round((rx2 - rx1) * 8 / 1e6, 1)
    tx_mbps = round((tx2 - tx1) * 8 / 1e6, 1)

    # DB stats
    db = load_db()
    user_count = sum(1 for k in db if not k.startswith("_"))
    conn_count = sum(len(v) for k, v in db.items() if not k.startswith("_") and isinstance(v, list))

    def fmt_bytes(b):
        """Human-readable bytes: KB → MB → GB → TB."""
        if b < 1024**2:
            return f"{b / 1024:.0f} KB"
        if b < 1024**3:
            return f"{b / 1024**2:.1f} MB"
        if b < 1024**4:
            return f"{b / 1024**3:.1f} GB"
        return f"{b / 1024**4:.2f} TB"

    # Top WG peers by traffic
    db_users = db.get("_users", {})
    top_lines = []
    sorted_peers = sorted(all_wg_peers, key=lambda p: p["rx"] + p["tx"], reverse=True)[:5]
    for p in sorted_peers:
        ip, rx, tx, active, pk = p["ip"], p["rx"], p["tx"], p["active"], p["pubkey"]
        # Try to find name: bot DB → WG-Easy names → pubkey prefix
        owner = None
        for uid, conns in db.items():
            if uid.startswith("_"):
                continue
            for c in (conns if isinstance(conns, list) else []):
                if c.get("ip") == ip or c.get("pubkey") == pk:
                    u = db_users.get(uid, {})
                    owner = f"@{u['username']}" if u.get("username") else u.get("first_name", uid)
                    break
            if owner:
                break
        if not owner:
            owner = wge_names.get(pk, pk[:12] + "...")
        st = "🟢" if active else "⚪"
        top_lines.append(f"{st} {owner} — ↓{fmt_bytes(rx)} ↑{fmt_bytes(tx)}")

    # Top xray clients by traffic
    sorted_xui = sorted(xui_clients, key=lambda r: r[1] + r[2], reverse=True)[:3]
    for email, up, down, _ in sorted_xui:
        top_lines.append(f"🔷 xray {email} — ↓{fmt_bytes(down)} ↑{fmt_bytes(up)}")

    top_str = "\n".join(top_lines) if top_lines else "нет данных"
    text = (
        f"📊 Статус сервера\n\n"
        f"CPU: {load1:.1f} / {load5:.1f} / {load15:.1f}\n"
        f"RAM: {used_mb}MB / {total_mb}MB ({round(used_mb/total_mb*100)}%)\n"
        f"Disk: {disk_free_gb}GB / {disk_total_gb}GB свободно\n"
        f"Сеть: ↓{rx_mbps} ↑{tx_mbps} Мбит/с\n\n"
        f"AWG: {len(awg_peers)} пиров ({sum(1 for p in awg_peers if p['active'])} онлайн)\n"
        f"WG-Easy: {len(wge_peers)} пиров ({sum(1 for p in wge_peers if p['active'])} онлайн)\n"
        f"X-UI: {len(xui_clients)} клиентов\n"
        f"Бот: {user_count} юзеров, {conn_count} подключений\n\n"
        f"Топ по трафику:\n{top_str}"
    )
    return text


# ── Telegram handlers ───────────────────────────────────────────────────

WELCOME_TEXT = (
    "📱 *Как подключиться к КВН*\n\n"

    "🌐 *Сохраните на случай, если Telegram перестанет работать:*\n"
    "`https://185.171.80.233:4443`\n"
    "Резервный сайт — через него можно получить конфиг без Telegram.\n"
    "Браузер покажет предупреждение о сертификате — это нормально, нажмите «Продолжить».\n\n"

    "*1. Скачайте приложение:*\n"
    "• Android — [AmneziaVPN (Google Play)](https://play.google.com/store/apps/details?id=org.amnezia.vpn)\n"
    "• iPhone (иностранный App Store) — [AmneziaVPN](https://apps.apple.com/app/amneziavpn/id1600529900)\n"
    "• iPhone (российский App Store) — [AmneziaWG](https://apps.apple.com/ru/app/amneziawg/id6478942365)\n\n"

    "*2. Получите конфиг:*\n"
    "Нажмите кнопку «🆕 Новое подключение» ниже → введите имя → скачайте файл\n\n"

    "*3. Импортируйте конфиг:*\n"
    "Нажмите на скачанный файл → «Поделиться» → ещё раз «Поделиться» → выберите приложение Amnezia → дайте все разрешения\n\n"

    "*4. Готово!*\n"
    "Можно не выключать — через сервис идёт только нужный трафик. "
    "На скорость и батарею не влияет.\n\n"

    "Если регистрировались через сайт — отправьте /verify КОД чтобы разблокировать все 3 подключения.\n"
    "По любым вопросам → /support"
)


def cmd_clients(update: Update, context: CallbackContext):
    """List bot clients with clickable TG links. Restricted to CLIENTS_VIEW_IDS."""
    user = update.effective_user
    if user.id not in CLIENTS_VIEW_IDS:
        return
    chat_log(user, "cmd_clients")
    _clear_states(user.id)

    import json
    try:
        db = json.loads(Path(__file__).parent.joinpath("users_db.json").read_text())
    except Exception as e:
        update.message.reply_text(f"Не смог прочитать users_db.json: {e}")
        return

    identities = {}
    log_path = Path(__file__).parent / "chat_log.jsonl"
    if log_path.exists():
        try:
            with open(log_path) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    uid = str(e.get("user_id", ""))
                    if uid:
                        identities[uid] = {
                            "username": e.get("username", ""),
                            "first": e.get("first_name", ""),
                            "last": e.get("last_name", ""),
                        }
        except Exception:
            pass

    """esc_html_clients_marker"""
    def esc(s):
        s = str(s)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = [(uid, cfg) for uid, cfg in db.items()
            if str(uid).lstrip("-").isdigit() and isinstance(cfg, list)]
    rows.sort(key=lambda kv: -len(kv[1]))
    header = "\U0001F465 <b>Клиенты бота</b> ({} юзеров)".format(len(rows))
    lines = [header, ""]
    for uid, configs in rows:
        meta = identities.get(str(uid), {})
        uname = meta.get("username", "")
        first = meta.get("first", "")
        last = meta.get("last", "")
        full = " ".join(p for p in [first, last] if p).strip()
        if uname:
            label = "@" + esc(uname)
            if full:
                label += " (" + esc(full) + ")"
            link = '<a href="tg://user?id={}">{}</a>'.format(uid, label)
        elif full:
            link = '<a href="tg://user?id={}">{}</a> <code>id:{}</code>'.format(uid, esc(full), uid)
        else:
            link = '<a href="tg://user?id={}">id:{}</a>'.format(uid, uid)

        types = {}
        for c in configs:
            if not isinstance(c, dict):
                continue
            t = c.get("type", "?")
            types[t] = types.get(t, 0) + 1
        type_str = ", ".join("{}:{}".format(t, n) for t, n in types.items())
        lines.append("\u2022 {} \u2014 {}".format(link, type_str))

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

    back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]])
    for i, ch in enumerate(chunks):
        is_last = (i == len(chunks) - 1)
        update.message.reply_text(ch, parse_mode="HTML", disable_web_page_preview=True,
                                  reply_markup=back_kb if is_last else None)



def _invite_link_html(bot_username, token, remaining_display, *, open_uses=None, expires_days=None):
    """Render the standard 'here is your invite link' message (HTML parse_mode)."""
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


def cb_invite_create(update: Update, context: CallbackContext):
    """Generate a single-use invite link (quota-limited for non-admins)."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id) and not invites.is_allowed(user.id):
        query.edit_message_text("🔒 Нет доступа.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return
    token, remaining = invites.create_token(user.id)
    rem_display = "∞" if remaining == -1 else remaining
    if not token:
        used, rem = invites.get_quota(user.id)
        pending = len(invites.list_pending_tokens(user.id))
        query.edit_message_text(
            f"🎟 Лимит приглашений исчерпан.\n\n"
            f"Использовано: {used} из {used + rem + pending}\n"
            f"Ожидают активации: {pending}\n\n"
            f"Когда кто-то активирует вашу ссылку, место освободится (если осталась квота).",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]),
        )
        return
    bot_username = context.bot.username
    body = _invite_link_html(bot_username, token, rem_display)
    query.edit_message_text(
        body, parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]),
        disable_web_page_preview=True,
    )


# ── Open (multi-use, admin-only) invite links ─────────────────────────

# callback_data shapes:
#   invite_open                    → show uses picker
#   invite_open_uses:<N|inf>       → selected uses, show expiry picker
#   invite_open_make:<N|inf>:<D|inf>  → create token
#   invite_open_list               → list user's active open tokens
#   invite_open_revoke:<token>     → revoke

def _invite_open_uses_kb():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("5", callback_data="invite_open_uses:5"),
            InlineKeyboardButton("10", callback_data="invite_open_uses:10"),
            InlineKeyboardButton("25", callback_data="invite_open_uses:25"),
            InlineKeyboardButton("∞", callback_data="invite_open_uses:inf"),
        ],
        [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
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


def cb_invite_open(update: Update, context: CallbackContext):
    """Step 1: admin chose «🔓 Открытая ссылка» — ask how many uses."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id):
        query.edit_message_text("🔒 Открытые ссылки доступны только админам.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return
    query.edit_message_text(
        "🔓 <b>Открытая ссылка</b>\n\n"
        "Сколько человек могут пройти по одной ссылке?",
        parse_mode="HTML",
        reply_markup=_invite_open_uses_kb(),
    )


def cb_invite_open_uses(update: Update, context: CallbackContext):
    """Step 2: admin picked uses count — ask expiry."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    uses = query.data.split(":", 1)[1]  # "5" / "10" / "25" / "inf"
    label = "без лимита" if uses == "inf" else f"до {uses} человек"
    query.edit_message_text(
        f"🔓 <b>Открытая ссылка</b>\n\n"
        f"Лимит: <b>{label}</b>\n\n"
        f"Срок действия ссылки?",
        parse_mode="HTML",
        reply_markup=_invite_open_expiry_kb(uses),
    )


def cb_invite_open_make(update: Update, context: CallbackContext):
    """Step 3: admin picked expiry — create the token."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    parts = query.data.split(":")
    if len(parts) != 3:
        query.edit_message_text("Ошибка формата кнопки.")
        return
    _, uses_s, days_s = parts

    max_uses = 10**9 if uses_s == "inf" else int(uses_s)
    expires_in_days = None if days_s == "inf" else int(days_s)

    token, _rem = invites.create_token(
        user.id, max_uses=max_uses, expires_in_days=expires_in_days,
    )
    if not token:
        query.edit_message_text("❌ Не удалось создать ссылку.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return

    bot_username = context.bot.username
    body = _invite_link_html(
        bot_username, token, None,
        open_uses=("inf" if uses_s == "inf" else int(uses_s)),
        expires_days=(None if days_s == "inf" else int(days_s)),
    )
    query.edit_message_text(
        body, parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🗂 Мои открытые ссылки", callback_data="invite_open_list")],
            [InlineKeyboardButton("⬅️ В меню", callback_data="back")],
        ]),
        disable_web_page_preview=True,
    )


def cb_invite_open_list(update: Update, context: CallbackContext):
    """Show admin's active open-tokens with a revoke button per row."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    tokens = invites.list_open_tokens(user.id)
    if not tokens:
        query.edit_message_text(
            "🗂 <b>Мои открытые ссылки</b>\n\nПока ни одной активной.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔓 Создать открытую", callback_data="invite_open")],
                [InlineKeyboardButton("⬅️ В меню", callback_data="back")],
            ]),
        )
        return

    import time as _time
    now = int(_time.time())
    lines = ["🗂 <b>Мои открытые ссылки</b>", ""]
    rows = []
    for tok, t in tokens:
        max_u = t.get("max_uses") or 1
        used = len(t["used_by"] if isinstance(t.get("used_by"), list) else ([] if not t.get("used_by") else [t["used_by"]]))
        exp = t.get("expires_at")
        if exp:
            days_left = max(0, (exp - now) // 86400)
            exp_str = f"{days_left} дн."
        else:
            exp_str = "∞"
        uses_str = "∞" if max_u >= 10**9 else str(max_u)
        label = f"{used}/{uses_str} · {exp_str} · {tok[:6]}…"
        rows.append([InlineKeyboardButton(f"🗑 {label}", callback_data=f"invite_open_revoke:{tok}")])
        lines.append(f"• <code>{tok}</code> — {used}/{uses_str}, осталось {exp_str}")
    rows.append([InlineKeyboardButton("🔓 Создать новую", callback_data="invite_open")])
    rows.append([InlineKeyboardButton("⬅️ В меню", callback_data="back")])
    query.edit_message_text(
        "\n".join(lines), parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(rows),
        disable_web_page_preview=True,
    )


def cb_invite_open_revoke(update: Update, context: CallbackContext):
    """Delete a multi-use token."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id):
        return
    tok = query.data.split(":", 1)[1]
    ok, msg = invites.revoke_token(tok, user.id)
    query.answer(msg, show_alert=False)
    # Re-render the list
    cb_invite_open_list(update, context)


def cb_clients_view(update: Update, context: CallbackContext):
    """Same as /clients but via button (admin-only)."""
    query = update.callback_query
    query.answer()
    user = query.from_user
    if user.id not in CLIENTS_VIEW_IDS:
        query.edit_message_text("🔒 Нет доступа.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return
    # Build a fake message object to reuse cmd_clients
    class _Msg:
        def __init__(self, chat_id, bot):
            self.chat_id = chat_id
            self._bot = bot
        def reply_text(self, text, **kwargs):
            kwargs.pop("reply_markup", None)
            self._bot.send_message(chat_id=self.chat_id, text=text, **kwargs)
    update.message = _Msg(query.message.chat_id, context.bot)
    cmd_clients(update, context)



PENDING_BCAST_FILE = Path(__file__).parent / "pending_broadcasts.json"

def _load_pending_bcast():
    import json as _j
    if not PENDING_BCAST_FILE.exists(): return {}
    try: return _j.loads(PENDING_BCAST_FILE.read_text())
    except Exception: return {}

def _save_pending_bcast(d):
    import json as _j
    PENDING_BCAST_FILE.write_text(_j.dumps(d, ensure_ascii=False))

def cb_bcast_send(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    user = query.from_user
    if not is_admin(user.id): return
    bcast_id = query.data.split(":", 1)[1] if ":" in query.data else ""
    pending = _load_pending_bcast()
    rec = pending.get(bcast_id)
    if not rec:
        query.edit_message_text("❌ Превью протухло, отправь заново.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return
    text = rec["text"]
    audience = rec.get("audience", "all")
    pending.pop(bcast_id, None)
    _save_pending_bcast(pending)
    query.edit_message_text("⏳ Запускаю рассылку...")
    try:
        _do_broadcast(user, text, context, audience=audience)
    except Exception as _e:
        logger.error(f"bcast send failed: {_e}")

def cb_bcast_cancel(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    bcast_id = query.data.split(":", 1)[1] if ":" in query.data else ""
    pending = _load_pending_bcast()
    pending.pop(bcast_id, None)
    _save_pending_bcast(pending)
    query.edit_message_text("❌ Рассылка отменена.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))


def cmd_start(update: Update, context: CallbackContext):
    user = update.effective_user
    args = context.args if hasattr(context, "args") else []
    logger.info(f"cmd_start from {user.id} (@{user.username}) args={args}")
    # Redeem invite token if provided
    if args:
        token = args[0].strip()
        logger.info(f"redeeming token={token} for user={user.id}")
        ok, msg = invites.redeem_token(token, user.id)
        if ok:
            update.message.reply_text(f"✅ {msg}")
        else:
            # If user is already allowed (admin/bootstrapped), ignore token silently
            if not invites.is_allowed(user.id):
                update.message.reply_text(f"❌ {msg}\n\nПопросите у знакомого рабочую пригласительную ссылку.")
                return
    # Access gate (with grandfather rule)
    if not is_admin(user.id) and not invites.is_allowed(user.id):
        # Grandfather: any user already present in users_db was admitted
        # before (legacy pre-invite era, web-verified via /verify, or
        # admin-created). Auto-add to allowlist so they are not blocked.
        _db_snap = load_db()
        _uid_key = str(user.id)
        if _uid_key in _db_snap or _uid_key in _db_snap.get("_users", {}):
            invites.ensure_allowed(user.id)
            logger.info(f"grandfathered {user.id} into allowlist (pre-existing in users_db)")
        else:
            update.message.reply_text(
                "🔒 Доступ к боту только по приглашению.\n\n"
                "Попросите у знакомого, который уже пользуется сервисом, прислать вам пригласительную ссылку."
            )
            return
    chat_log(user, "start")
    _clear_states(user.id)

    # Send welcome instruction on first visit
    db = load_db()
    uid = str(user.id)
    users_meta = db.get("_users", {})
    is_first = uid not in users_meta

    if is_first:
        try:
            update.message.reply_text(
                WELCOME_TEXT,
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
        except Exception as e:
            # Fallback without formatting — strip Markdown chars to keep it readable
            logger.warning(f"WELCOME_TEXT Markdown failed: {e}; sending plain text")
            plain = WELCOME_TEXT
            for ch in ("*", "`"):
                plain = plain.replace(ch, "")
            update.message.reply_text(plain, disable_web_page_preview=True)

    show_main_menu(update, context)


def cmd_new(update: Update, context: CallbackContext):
    chat_log(update.effective_user, "cmd_new")
    user = update.effective_user
    _clear_states(user.id)

    db = load_db()
    user_conns = db.get(str(user.id), [])
    if not is_admin(user.id) and len(user_conns) >= MAX_CONNECTIONS:
        update.message.reply_text(
            f"Достигнут лимит: {MAX_CONNECTIONS} подключений.\nУдалите одно из существующих."
        )
        return

    # Ask which type of connection to create
    keyboard = [
        [InlineKeyboardButton("🟢 Amnezia (рекомендуется)", callback_data="new_awg")],
        [InlineKeyboardButton("🌍 YouTube без рекламы (для заграницы)", callback_data="new_youtube")],
        [InlineKeyboardButton("🟣 XRay — только для Happ", callback_data="new_xray")],
        [InlineKeyboardButton("🆘 Чистый — если первые два не работают", callback_data="new_clean")],
        [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
    ]
    update.message.reply_text(
        "Какой тип подключения создать?\n\n"
        "🟢 *Amnezia* — основной режим, через сервер идёт только нужный трафик\n"
        "🌍 *YouTube без рекламы* — для тех, кто живёт заграницей. В РФ реклама на YouTube уже отключена в основном Amnezia-конфиге\n"
        "🟣 *XRay* — VLESS+Reality, для Happ\n"
        "🆘 *Чистый* — весь трафик через сервер, помогает когда первые два не работают",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown",
    )


def cmd_my(update: Update, context: CallbackContext):
    chat_log(update.effective_user, "cmd_my")
    _clear_states(update.effective_user.id)
    _show_connections(update.effective_user, update.message, context)


def cmd_support(update: Update, context: CallbackContext):
    user = update.effective_user
    chat_log(user, "cmd_support")
    _clear_states(user.id)
    # If sender is admin, message goes to OTHER admins. If they're alone — refuse.
    recipients = SUPPORT_IDS - {user.id}
    if not recipients:
        update.message.reply_text("Вам некому писать — других админов в support-листе нет 😄")
        return
    AWAITING_SUPPORT.add(user.id)
    update.message.reply_text(
        "✉️ Напишите ваше сообщение, и оно будет отправлено администратору.\n"
        "Для отмены нажмите /start"
    )


def _clear_states(uid):
    AWAITING_NAME.discard(uid)
    AWAITING_SUPPORT.discard(uid)
    AWAITING_REPLY.pop(uid, None)
    PENDING_TYPE.pop(uid, None)
    AWAITING_BROADCAST.discard(uid)
    BROADCAST_AUDIENCE.pop(uid, None)
    AWAITING_MY_DOMAIN.discard(uid)
    AWAITING_ADMIN_DOMAIN.discard(uid)


# ── /my_domains: per-user custom domains ────────────────────────────────

def _mydom_menu_kb(uid_str: str):
    """Return (text, InlineKeyboardMarkup) for the /my_domains menu."""
    domains = ud.list_domains(USER_DOMAINS_FILE, uid_str)
    if domains:
        body_lines = ["*Твои домены:*"]
        for e in domains:
            body_lines.append(f"• `{e['domain']}`")
        body = "\n".join(body_lines)
    else:
        body = "*Твои домены:* _пока пусто_\n\nДобавь домен — его IP будут доступны через VPN в split-режиме."

    rows = [[InlineKeyboardButton("➕ Добавить", callback_data="mydom_add")]]
    if domains:
        rows.append([InlineKeyboardButton("➖ Удалить", callback_data="mydom_remove")])
    rows.append([InlineKeyboardButton("⬅️ В меню", callback_data="back")])
    return body, InlineKeyboardMarkup(rows)


def cmd_my_domains(update: Update, context: CallbackContext):
    user = update.effective_user
    chat_log(user, "cmd_my_domains")
    _clear_states(user.id)
    body, kb = _mydom_menu_kb(str(user.id))
    update.message.reply_text(body, reply_markup=kb, parse_mode="Markdown")


def cb_my_domains_menu(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    _clear_states(q.from_user.id)
    body, kb = _mydom_menu_kb(str(q.from_user.id))
    try:
        q.edit_message_text(body, reply_markup=kb, parse_mode="Markdown")
    except Exception:
        q.message.reply_text(body, reply_markup=kb, parse_mode="Markdown")


def cb_mydom_add(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    uid = q.from_user.id
    AWAITING_MY_DOMAIN.add(uid)
    prompt = "Пришли домен (например: `netflix.com`)\n\nЛимит: 10 доменов."
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Отмена", callback_data="mydom_cancel")]])
    try:
        q.edit_message_text(prompt, reply_markup=kb, parse_mode="Markdown")
    except Exception:
        q.message.reply_text(prompt, reply_markup=kb, parse_mode="Markdown")


def cb_mydom_cancel(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    uid = q.from_user.id
    AWAITING_MY_DOMAIN.discard(uid)
    body, kb = _mydom_menu_kb(str(uid))
    try:
        q.edit_message_text(body, reply_markup=kb, parse_mode="Markdown")
    except Exception:
        q.message.reply_text(body, reply_markup=kb, parse_mode="Markdown")


def cb_mydom_remove(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    uid = str(q.from_user.id)
    domains = ud.list_domains(USER_DOMAINS_FILE, uid)
    if not domains:
        q.edit_message_text(
            "Список пуст.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅️ К списку", callback_data="my_domains_menu")]]
            ),
        )
        return
    rows = [[InlineKeyboardButton(f"🗑 {e['domain']}", callback_data=f"mydom_del:{e['domain']}")] for e in domains]
    rows.append([InlineKeyboardButton("⬅️ К списку", callback_data="my_domains_menu")])
    q.edit_message_text("*Выбери домен для удаления:*", reply_markup=InlineKeyboardMarkup(rows), parse_mode="Markdown")


def cb_mydom_del(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    uid = str(q.from_user.id)
    payload = q.data.split(":", 1)
    if len(payload) != 2:
        q.edit_message_text("Ошибка формата кнопки.")
        return
    domain = payload[1]
    ok, msg = ud.remove_domain(USER_DOMAINS_FILE, uid, domain)
    body, kb = _mydom_menu_kb(uid)
    tail = "\n\n" + msg + ("\n\n_Скачай конфиг заново — IPs обновились._" if ok else "")
    q.edit_message_text(body + tail, reply_markup=kb, parse_mode="Markdown")


# ── /admin_domains: global domain list (admin-only) ─────────────────────

def _trigger_fetch_lists():
    """Run fetch_lists.py in background — rebuilds allowed_ips.json with new admin domains."""
    try:
        subprocess.Popen(
            ["/usr/bin/python3", str(FETCH_LISTS_SCRIPT)],
            cwd=str(Path(FETCH_LISTS_SCRIPT).parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        logger.info("admin_domains: fetch_lists.py triggered")
    except Exception as e:
        logger.warning(f"admin_domains: failed to trigger fetch_lists: {e!r}")


def _admindom_menu_kb():
    """Return (text, InlineKeyboardMarkup) for the /admin_domains menu."""
    domains = ud.list_admin_domains(ADMIN_DOMAINS_FILE)
    if domains:
        body = "*🌎 Общие домены (всем юзерам):*\n" + "\n".join(f"• `{d}`" for d in domains)
    else:
        body = "*🌎 Общие домены:* _пусто_\n\nДомены тут попадают в split-конфиг _всех_ юзеров после `fetch_lists`."

    rows = [[InlineKeyboardButton("➕ Добавить", callback_data="admindom_add")]]
    if domains:
        rows.append([InlineKeyboardButton("➖ Удалить", callback_data="admindom_remove")])
    rows.append([InlineKeyboardButton("⬅️ В меню", callback_data="back")])
    return body, InlineKeyboardMarkup(rows)


def cmd_admin_domains(update: Update, context: CallbackContext):
    user = update.effective_user
    if not is_admin(user.id):
        update.message.reply_text("🔒 Команда только для админа.")
        return
    chat_log(user, "cmd_admin_domains")
    _clear_states(user.id)
    body, kb = _admindom_menu_kb()
    update.message.reply_text(body, reply_markup=kb, parse_mode="Markdown")


def cb_admindom_menu(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    if not is_admin(q.from_user.id):
        q.edit_message_text("🔒 Только для админа.")
        return
    _clear_states(q.from_user.id)
    body, kb = _admindom_menu_kb()
    try:
        q.edit_message_text(body, reply_markup=kb, parse_mode="Markdown")
    except Exception:
        q.message.reply_text(body, reply_markup=kb, parse_mode="Markdown")


def cb_admindom_add(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    if not is_admin(q.from_user.id):
        q.edit_message_text("🔒 Только для админа.")
        return
    AWAITING_ADMIN_DOMAIN.add(q.from_user.id)
    prompt = "Пришли домен для *общего* списка (попадёт всем):\n\nПример: `netflix.com`"
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Отмена", callback_data="admindom_cancel")]])
    try:
        q.edit_message_text(prompt, reply_markup=kb, parse_mode="Markdown")
    except Exception:
        q.message.reply_text(prompt, reply_markup=kb, parse_mode="Markdown")


def cb_admindom_cancel(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    AWAITING_ADMIN_DOMAIN.discard(q.from_user.id)
    body, kb = _admindom_menu_kb()
    try:
        q.edit_message_text(body, reply_markup=kb, parse_mode="Markdown")
    except Exception:
        q.message.reply_text(body, reply_markup=kb, parse_mode="Markdown")


def cb_admindom_remove(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    if not is_admin(q.from_user.id):
        q.edit_message_text("🔒 Только для админа.")
        return
    domains = ud.list_admin_domains(ADMIN_DOMAINS_FILE)
    if not domains:
        q.edit_message_text(
            "Общий список пуст.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅️ К списку", callback_data="admindom_menu")]]
            ),
        )
        return
    rows = [[InlineKeyboardButton(f"🗑 {d}", callback_data=f"admindom_del:{d}")] for d in domains]
    rows.append([InlineKeyboardButton("⬅️ К списку", callback_data="admindom_menu")])
    q.edit_message_text("*Выбери домен для удаления из общего списка:*", reply_markup=InlineKeyboardMarkup(rows), parse_mode="Markdown")


def cb_admindom_del(update: Update, context: CallbackContext):
    q = update.callback_query
    q.answer()
    if not is_admin(q.from_user.id):
        q.edit_message_text("🔒 Только для админа.")
        return
    payload = q.data.split(":", 1)
    if len(payload) != 2:
        q.edit_message_text("Ошибка формата кнопки.")
        return
    domain = payload[1]
    ok, msg = ud.remove_admin_domain(ADMIN_DOMAINS_FILE, domain)
    if ok:
        _trigger_fetch_lists()
    body, kb = _admindom_menu_kb()
    tail = "\n\n" + msg + ("\n\n⏳ _Пересобираю общий список (~30 сек), потом юзерам скачивать заново._" if ok else "")
    q.edit_message_text(body + tail, reply_markup=kb, parse_mode="Markdown")


def _receive_admin_domain(update: Update, context: CallbackContext, text: str):
    user = update.effective_user
    chat_log(user, "admindom_add", f"input={text!r}")
    ok, msg = ud.add_admin_domain(ADMIN_DOMAINS_FILE, text)
    if ok:
        _trigger_fetch_lists()

    rows = []
    if ok:
        rows.append([InlineKeyboardButton("🌎 К общим доменам", callback_data="admindom_menu")])
        tail = "\n\n⏳ _Пересобираю общий список (~30 сек) — затем всем юзерам новые IPs подтянутся при следующем скачивании конфига._"
    else:
        rows.append([InlineKeyboardButton("🔄 Попробовать ещё", callback_data="admindom_add")])
        rows.append([InlineKeyboardButton("🌎 К общим доменам", callback_data="admindom_menu")])
        tail = ""

    update.message.reply_text(msg + tail, reply_markup=InlineKeyboardMarkup(rows), parse_mode="Markdown")


def show_main_menu(update: Update, context: CallbackContext):
    db = load_db()
    user = update.effective_user
    uid = str(user.id)
    save_user_info(db, user)
    save_db(db)
    count = len(db.get(uid, []))
    dom_count = len(ud.list_domains(USER_DOMAINS_FILE, uid))
    admin = is_admin(user.id)

    keyboard = []
    if admin:
        adm_dom_count = len(ud.list_admin_domains(ADMIN_DOMAINS_FILE))
        keyboard.append([InlineKeyboardButton("🆕 Новое подключение", callback_data="new_conn")])
        keyboard.append([InlineKeyboardButton(f"📋 Мои подключения ({count})", callback_data="list_conns")])
        keyboard.append([InlineKeyboardButton(f"🌐 Мои домены ({dom_count})", callback_data="my_domains_menu")])
        keyboard.append([InlineKeyboardButton(f"🌎 Общие домены всем ({adm_dom_count})", callback_data="admindom_menu")])
        keyboard.append([InlineKeyboardButton("📋 Все подключения", callback_data="list_all_conns")])
        keyboard.append([InlineKeyboardButton("📊 Статус сервера", callback_data="server_stats")])
        keyboard.append([InlineKeyboardButton("📢 Рассылка всем", callback_data="broadcast")])
        # Show "write to admins" only if there are OTHER admins to write to
        if SUPPORT_IDS - {user.id}:
            keyboard.append([InlineKeyboardButton("✉️ Написать остальным админам", callback_data="support")])
    else:
        keyboard.append([InlineKeyboardButton(f"🆕 Новое подключение ({count}/{MAX_CONNECTIONS})", callback_data="new_conn")])
        keyboard.append([InlineKeyboardButton(f"📋 Мои подключения ({count})", callback_data="list_conns")])
        keyboard.append([InlineKeyboardButton(f"🌐 Мои домены ({dom_count})", callback_data="my_domains_menu")])
        keyboard.append([InlineKeyboardButton("✉️ Написать админу", callback_data="support")])

    # Invite button for all allowed users (except fresh no-access paths — already gated above)
    used, remaining = invites.get_quota(user.id)
    if remaining == -1:
        invite_label = "🎟 Пригласить друга (∞)"
    else:
        invite_label = "🎟 Пригласить друга ({}/{})".format(remaining, used + remaining)
    keyboard.append([InlineKeyboardButton(invite_label, callback_data="invite_create")])

    # Admin-only: open (multi-use) invite link management
    if is_admin(user.id):
        keyboard.append([InlineKeyboardButton("🔓 Открытая ссылка (admin)", callback_data="invite_open")])
        if invites.list_open_tokens(user.id):
            keyboard.append([InlineKeyboardButton("🗂 Мои открытые ссылки", callback_data="invite_open_list")])

    # Admin-only "Clients" button for CLIENTS_VIEW_IDS members
    if user.id in CLIENTS_VIEW_IDS:
        keyboard.append([InlineKeyboardButton("👥 Клиенты бота", callback_data="clients_view")])


    text = (
        "🔐 *КВН*\n\n"
        "🌐 *Резервный сайт (если Telegram недоступен):*\n"
        f"`https://{SERVER_IP}:4443`\n"
        "⚠️ Откройте в браузере (Safari / Chrome), не в Telegram. "
        "Браузер покажет «Небезопасный сертификат» — это нормально, "
        "нажмите «Продолжить». Сертификат самоподписанный для шифрования передачи ключей.\n\n"
        "📲 *Скачать приложение:*\n"
        "📱 Android — [AmneziaVPN](https://play.google.com/store/apps/details?id=org.amnezia.vpn)\n"
        "🍏 iPhone (иностр.) — [AmneziaVPN](https://apps.apple.com/app/amneziavpn/id1600529900)\n"
        "🍏 iPhone (рос.) — [AmneziaWG](https://apps.apple.com/ru/app/amneziawg/id6478942365)\n\n"
        "Выбери действие:"
    )

    if update.callback_query:
        update.callback_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
    else:
        (update.message or context.bot.send_message(chat_id=update.effective_chat.id, text="")).reply_text(
            text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown"
        ) if update.message else context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown"
        )


def _send_menu(bot, chat_id, text, keyboard):
    bot.send_message(chat_id=chat_id, text=text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")


def button_handler(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    data = query.data
    user = update.effective_user

    chat_log(user, "button", data)
    _clear_states(user.id)

    if data == "new_conn":
        _handle_new_conn(query, user, context)
    elif data == "new_awg":
        PENDING_TYPE[user.id] = "awg"
        _ask_connection_name(user, query, context)
    elif data == "new_xray":
        PENDING_TYPE[user.id] = "xray"
        _ask_connection_name(user, query, context)
    elif data == "new_clean":
        PENDING_TYPE[user.id] = "clean"
        _ask_connection_name(user, query, context)
    elif data == "new_youtube":
        PENDING_TYPE[user.id] = "youtube"
        _ask_connection_name(user, query, context)
    elif data == "list_conns":
        _handle_list_conns(query, user, context, admin_view=False)
    elif data == "list_all_conns":
        _handle_list_conns(query, user, context, admin_view=True, section="awg2")
    elif data == "list_all_wge":
        _handle_list_conns(query, user, context, admin_view=True, section="wge")
    elif data == "list_all_xui":
        _handle_list_conns(query, user, context, admin_view=True, section="xui")
    elif data.startswith("view_"):
        _handle_view_conn(query, user, context, data[5:])
    elif data.startswith("download_"):
        _handle_download(query, user, context, data[9:])
    elif data.startswith("delete_"):
        _handle_delete_conn(query, user, context, data[7:])
    elif data.startswith("confirm_delete_"):
        _handle_confirm_delete(query, user, context, data[15:])
    elif data == "support":
        if is_admin(user.id):
            query.edit_message_text("Вы админ 😄", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
            return
        AWAITING_SUPPORT.add(user.id)
        keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
        query.edit_message_text(
            "✉️ Напишите ваше сообщение, и оно будет отправлено администратору:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif data.startswith("reply_to_"):
        target_uid = int(data[9:])
        AWAITING_REPLY[user.id] = target_uid
        query.edit_message_text(f"Введите ответ пользователю (id:{target_uid}):")
    elif data == "server_stats":
        _handle_server_stats(query, user, context)
    elif data == "broadcast":
        if not is_admin(user.id):
            return
        # Show submenu — choose audience
        keyboard = [
            [InlineKeyboardButton("🧪 Тестовая (только мне)", callback_data="bcast_test")],
            [InlineKeyboardButton("🟢 Только активным (7 дней)", callback_data="bcast_active")],
            [InlineKeyboardButton("📢 Всем", callback_data="bcast_all")],
            [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
        ]
        query.edit_message_text(
            "📢 *Рассылка*\n\nКому отправить сообщение?",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown",
        )
    elif data in ("bcast_test", "bcast_active", "bcast_all"):
        if not is_admin(user.id):
            return
        # Map to audience type
        BROADCAST_AUDIENCE[user.id] = data[6:]  # 'test', 'active', 'all'
        AWAITING_BROADCAST.add(user.id)
        labels = {"test": "тестовая (только мне)", "active": "активным за 7 дней", "all": "всем пользователям"}
        keyboard = [[InlineKeyboardButton("⬅️ Отмена", callback_data="back")]]
        query.edit_message_text(
            f"📢 *Рассылка: {labels[data[6:]]}*\n\n"
            "Отправьте текст сообщения. Поддерживается Markdown.",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown",
        )
    elif data == "back":
        show_main_menu(update, context)
    elif data == "back_to_list":
        if is_admin(user.id):
            _handle_list_conns(query, user, context, admin_view=True)
        else:
            _handle_list_conns(query, user, context, admin_view=False)


# ── New connection ──────────────────────────────────────────────────────

# Per-user selection of connection type to create next (tg_id -> "awg" | "xray")
PENDING_TYPE = {}


def _handle_new_conn(query, user, context):
    db = load_db()
    uid = str(user.id)
    user_conns = db.get(uid, [])

    if not is_admin(user.id) and len(user_conns) >= MAX_CONNECTIONS:
        keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
        query.edit_message_text(
            f"Достигнут лимит: {MAX_CONNECTIONS} подключений.\nУдалите одно из существующих.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    # Ask which type of connection to create
    keyboard = [
        [InlineKeyboardButton("🟢 Amnezia (рекомендуется)", callback_data="new_awg")],
        [InlineKeyboardButton("🌍 YouTube без рекламы (для заграницы)", callback_data="new_youtube")],
        [InlineKeyboardButton("🟣 XRay — только для Happ", callback_data="new_xray")],
        [InlineKeyboardButton("🆘 Чистый — если первые два не работают", callback_data="new_clean")],
        [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
    ]
    query.edit_message_text(
        "Какой тип подключения создать?\n\n"
        "🟢 *Amnezia* — основной режим, через сервер идёт только нужный трафик\n"
        "🌍 *YouTube без рекламы* — для тех, кто живёт заграницей. В РФ реклама на YouTube уже отключена в основном Amnezia-конфиге\n"
        "🟣 *XRay* — VLESS+Reality, для Happ\n"
        "🆘 *Чистый* — весь трафик через сервер, помогает когда первые два не работают",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown",
    )


def _ask_connection_name(user, msg_or_query, context):
    AWAITING_NAME.add(user.id)
    keyboard = [[InlineKeyboardButton("⬅️ Отмена", callback_data="back")]]
    text = "Введите имя для подключения (например: iPhone, работа, планшет):"
    if hasattr(msg_or_query, 'edit_message_text'):
        msg_or_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        msg_or_query.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard))


# ── List connections ────────────────────────────────────────────────────

def _handle_list_conns(query, user, context, admin_view=False, section="awg2"):
    db = load_db()
    db_users = db.get("_users", {})

    if admin_view and is_admin(user.id):
        if section == "awg2":
            keyboard = []
            for uid, conns in sorted(db.items()):
                if uid.startswith("_") or not isinstance(conns, list) or not conns:
                    continue
                u = db_users.get(uid, {})
                uname = f"@{u['username']}" if u.get("username") else u.get("first_name", f"id:{uid}")
                for conn in conns:
                    icon = "🟣" if conn_type(conn) == "xray" else "🟢"
                    detail = conn.get("ip", "xray") if conn_type(conn) == "awg" else "xray"
                    label = f"{uname} — {icon} {conn['name']} ({detail})"
                    keyboard.append([InlineKeyboardButton(label, callback_data=f"view_{conn_key(conn)}")])
            count = sum(len(v) for k,v in db.items() if not k.startswith('_') and isinstance(v,list))
            keyboard.append([
                InlineKeyboardButton("WG-Easy ▸", callback_data="list_all_wge"),
                InlineKeyboardButton("X-UI ▸", callback_data="list_all_xui"),
            ])
            keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data="back")])
            query.edit_message_text(
                f"📋 *AWG 2.0* ({count} шт.)",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )

        elif section == "wge":
            try:
                out = subprocess.run(
                    ["docker", "exec", "amnezia-wg-easy", "cat", "/etc/wireguard/wg0.json"],
                    capture_output=True, text=True, timeout=5
                ).stdout
                clients = json.loads(out).get("clients", {})
            except Exception:
                clients = {}
            lines = []
            for cid, c in sorted(clients.items(), key=lambda x: x[1].get("name", "")):
                name = c.get("name", "?")
                ip = c.get("address", "?")
                enabled = "🟢" if c.get("enabled", True) else "🔴"
                lines.append(f"{enabled} {name} — {ip}")
            text = f"📋 WG-Easy ({len(clients)} шт.)\n\n" + "\n".join(lines) if lines else "Нет подключений"
            keyboard = [
                [
                    InlineKeyboardButton("◂ AWG 2.0", callback_data="list_all_conns"),
                    InlineKeyboardButton("X-UI ▸", callback_data="list_all_xui"),
                ],
                [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
            ]
            query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))

        elif section == "xui":
            try:
                import sqlite3
                conn_db = sqlite3.connect("/etc/x-ui/x-ui.db")
                rows = conn_db.execute("SELECT email, up, down, enable FROM client_traffics ORDER BY email").fetchall()
                conn_db.close()
            except Exception:
                rows = []

            def _fb(b):
                if b < 1024**3:
                    return f"{b / 1024**2:.0f}MB"
                return f"{b / 1024**3:.1f}GB"

            lines = []
            for email, up, down, enabled in rows:
                st = "🟢" if enabled else "🔴"
                lines.append(f"{st} {email} — ↓{_fb(down)} ↑{_fb(up)}")
            text = f"📋 X-UI ({len(rows)} шт.)\n\n" + "\n".join(lines) if lines else "Нет клиентов"
            keyboard = [
                [
                    InlineKeyboardButton("◂ AWG 2.0", callback_data="list_all_conns"),
                    InlineKeyboardButton("◂ WG-Easy", callback_data="list_all_wge"),
                ],
                [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
            ]
            query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        uid = str(user.id)
        user_conns = db.get(uid, [])
        if not user_conns:
            keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
            query.edit_message_text("У вас нет подключений.", reply_markup=InlineKeyboardMarkup(keyboard))
            return
        keyboard = []
        for conn in user_conns:
            keyboard.append([InlineKeyboardButton(
                _conn_label(conn),
                callback_data=f"view_{conn_key(conn)}"
            )])
        keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data="back")])
        query.edit_message_text(
            f"📋 *Мои подключения* ({len(user_conns)})",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown"
        )


def _conn_label(conn):
    """Short human label for a connection."""
    ctype = conn_type(conn)
    if ctype == "xray":
        return f"🟣 {conn['name']}"
    return f"🟢 {conn['name']} — {conn.get('ip', '?')}"


def _show_connections(user, message, context):
    """For /my command."""
    db = load_db()
    uid = str(user.id)
    user_conns = db.get(uid, [])
    if not user_conns:
        message.reply_text("У вас нет подключений.")
        return
    keyboard = []
    for conn in user_conns:
        keyboard.append([InlineKeyboardButton(
            _conn_label(conn),
            callback_data=f"view_{conn_key(conn)}"
        )])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data="back")])
    message.reply_text(
        f"📋 *Мои подключения* ({len(user_conns)})",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )


# ── View single connection ──────────────────────────────────────────────

def _handle_view_conn(query, user, context, ident):
    db = load_db()
    owner_uid, conn = find_conn_owner(db, ident)
    if not conn:
        keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
        query.edit_message_text("Подключение не найдено.", reply_markup=InlineKeyboardMarkup(keyboard))
        return

    # Ownership check
    if str(user.id) != owner_uid and not is_admin(user.id):
        keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
        query.edit_message_text("Нет доступа.", reply_markup=InlineKeyboardMarkup(keyboard))
        return

    db_users = db.get("_users", {})
    u = db_users.get(owner_uid, {})
    owner_label = f"@{u['username']}" if u.get("username") else u.get("first_name", f"id:{owner_uid}")

    ctype = conn_type(conn)
    type_label = "🟣 XRay (VLESS)" if ctype == "xray" else "🟢 Amnezia"

    text = f"📱 *{conn['name']}*\n"
    text += f"📦 {type_label}\n"
    if is_admin(user.id):
        text += f"👤 {owner_label}\n"
    if ctype == "awg":
        text += f"🌐 IP: `{conn['ip']}`\n"
    text += f"📅 Создано: {conn.get('created', '?')}\n"

    key = conn_key(conn)
    has_config = bool(conn.get("privkey") or conn.get("uuid"))

    keyboard = []
    if has_config:
        keyboard.append([InlineKeyboardButton("📥 Скачать конфиг", callback_data=f"download_{key}")])
    keyboard.append([InlineKeyboardButton("🗑 Удалить", callback_data=f"delete_{key}")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data="back_to_list")])

    query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")


# ── Download config ─────────────────────────────────────────────────────

def _handle_download(query, user, context, ident):
    db = load_db()
    owner_uid, conn = find_conn_owner(db, ident)
    if not conn:
        query.edit_message_text("Подключение не найдено.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return

    if str(user.id) != owner_uid and not is_admin(user.id):
        query.edit_message_text("Нет прав.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return

    safe_name = re.sub(r'[^\w\-]', '_', conn['name'])
    ctype = conn_type(conn)

    if ctype == "xray":
        client_uuid = conn["uuid"]
        try:
            json_file = xray_helper.build_plain_xray_json(client_uuid)
        except Exception as e:
            query.edit_message_text(f"❌ Ошибка генерации XRay-конфига: {e}", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
            return

        context.bot.send_document(
            chat_id=query.message.chat_id,
            document=json_file.encode("utf-8"),
            filename=f"kvn_{safe_name}.json",
            caption=(
                f"📱 *{conn['name']}* — XRay JSON со встроенными правилами маршрутизации\n\n"
                "📥 *Рекомендуемый клиент — Happ:*\n"
                "🍏 iPhone (иностр.) — [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215)\n"
                "🍏 iPhone (рос.) — [Happ](https://apps.apple.com/ru/app/happ-proxy-utility/id6504287215)\n"
                "📱 Android — [Happ (Google Play)](https://play.google.com/store/apps/details?id=com.happproxy)\n\n"
                "*Альтернативы (иностр. App Store):* "
                "[V2Box](https://apps.apple.com/app/v2box-v2ray-client/id6446814690), "
                "[Streisand](https://apps.apple.com/app/streisand/id6450534064), "
                "[FoXray](https://apps.apple.com/app/foxray/id6448898396). "
                "Android: [v2rayNG](https://play.google.com/store/apps/details?id=com.v2ray.ang)\n\n"
                "Импорт: «Добавить конфиг» → «Из файла»"
            ),
            parse_mode="Markdown",
        )
        chat_log(user, "download_config", f"type=xray name={conn['name']}")
        return

    # AWG default
    privkey = conn.get("privkey")
    if not privkey:
        query.edit_message_text("⚠️ Для этого подключения конфиг недоступен (создано до обновления).\nУдалите и создайте заново.")
        return

    psk = conn.get("psk", get_psk())
    tunnel = conn.get("tunnel", "split")
    if tunnel is True:
        tunnel = "full"
    elif tunnel is False:
        tunnel = "split"
    config = generate_client_config(privkey, conn["ip"], psk, mode=tunnel, user_id=owner_uid)
    prefix = {"full": "clean_", "youtube": "youtube_"}.get(tunnel, "")
    filename = f"awg_{prefix}{safe_name}.conf"

    if tunnel == "full":
        cap = (
            f"📱 *{conn['name']}* (чистый, весь трафик через сервер)\n\n"
            f"{INSTRUCTION_TEXT_CLEAN}"
        )
    elif tunnel == "youtube":
        cap = (
            f"📱 *{conn['name']}* (только YouTube)\n\n"
            f"{INSTRUCTION_TEXT}"
        )
    else:
        cap = f"📱 *{conn['name']}*\n\n{INSTRUCTION_TEXT}"

    context.bot.send_document(
        chat_id=query.message.chat_id,
        document=config.encode("utf-8"),
        filename=filename,
        caption=cap,
        parse_mode="Markdown",
    )
    chat_log(user, "download_config", f"type=awg name={conn['name']} tunnel={tunnel}")


# ── Delete connection ───────────────────────────────────────────────────

def _handle_delete_conn(query, user, context, ident):
    db = load_db()
    owner_uid, conn = find_conn_owner(db, ident)
    if not conn:
        keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
        query.edit_message_text("Подключение не найдено.", reply_markup=InlineKeyboardMarkup(keyboard))
        return

    if str(user.id) != owner_uid and not is_admin(user.id):
        query.edit_message_text("Нет прав.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]))
        return

    key = conn_key(conn)
    detail = conn.get("ip") if conn_type(conn) == "awg" else "XRay"
    keyboard = [
        [InlineKeyboardButton(f"🗑 Да, удалить «{conn['name']}»", callback_data=f"confirm_delete_{key}")],
        [InlineKeyboardButton("⬅️ Отмена", callback_data=f"view_{key}")],
    ]
    query.edit_message_text(
        f"Удалить подключение *{conn['name']}* (`{detail}`)?",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )


def _handle_confirm_delete(query, user, context, ident):
    query.edit_message_text("Удаляю подключение...")
    err = delete_connection_by_pubkey(user, ident)
    if err:
        keyboard = [[InlineKeyboardButton("⬅️ Назад", callback_data="back")]]
        query.edit_message_text(f"Ошибка: {err}", reply_markup=InlineKeyboardMarkup(keyboard))
        return
    keyboard = [[InlineKeyboardButton("⬅️ В меню", callback_data="back")]]
    query.edit_message_text("✅ Подключение удалено.", reply_markup=InlineKeyboardMarkup(keyboard))


# ── Server stats (admin) ───────────────────────────────────────────────

def _handle_server_stats(query, user, context):
    if not is_admin(user.id):
        return
    query.edit_message_text("⏳ Собираю статистику...")
    text = get_server_stats()
    keyboard = [
        [InlineKeyboardButton("🔄 Обновить", callback_data="server_stats")],
        [InlineKeyboardButton("⬅️ Назад", callback_data="back")],
    ]
    query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(keyboard))


# ── Support flow ────────────────────────────────────────────────────────

def _handle_support_message(user, text, context):
    """User sent a support message — forward to SUPPORT_IDS (excluding sender)."""
    label = tg_user_label(user)
    sender_role = "админа" if is_admin(user.id) else "пользователя"
    recipients = SUPPORT_IDS - {user.id}
    sent = 0
    for admin_id in recipients:
        keyboard = [[InlineKeyboardButton("💬 Ответить", callback_data=f"reply_to_{user.id}")]]
        try:
            context.bot.send_message(
                chat_id=admin_id,
                text=f"✉️ *Сообщение от {sender_role} {label}:*\n\n{text}",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown",
            )
            sent += 1
            logger.info(f"Support msg from {user.id} delivered to admin {admin_id}")
        except Exception:
            try:
                context.bot.send_message(
                    chat_id=admin_id,
                    text=f"✉️ Сообщение от {sender_role} {label}:\n\n{text}",
                    reply_markup=InlineKeyboardMarkup(keyboard),
                )
                sent += 1
            except Exception as e:
                logger.error(f"Failed to send support msg to {admin_id}: {e}")

    chat_log(user, "support_message", f"recipients={len(recipients)} sent={sent} text={text[:200]}")
    return sent


def _handle_admin_reply(admin_id, target_uid, text, context):
    """Admin replied to a user."""
    try:
        context.bot.send_message(
            chat_id=target_uid,
            text=f"💬 *Ответ от администратора:*\n\n{text}",
            parse_mode="Markdown"
        )
        context.bot.send_message(
            chat_id=admin_id,
            text=f"✅ Ответ отправлен пользователю (id:{target_uid})"
        )
    except Exception as e:
        context.bot.send_message(chat_id=admin_id, text=f"❌ Ошибка: {e}")

    chat_log_entry = {"id": admin_id, "username": "", "first_name": "admin", "last_name": ""}

    class FakeUser:
        def __init__(self, uid):
            self.id = uid
            self.username = "admin"
            self.first_name = "admin"
            self.last_name = ""
    chat_log(FakeUser(admin_id), "admin_reply", f"to={target_uid} text={text[:200]}")


def _do_broadcast(admin_user, text, context, audience="all"):
    """Send a message to selected audience.
    audience: 'test' (only admin), 'active' (handshake < 7 days), 'all' (everyone)
    """
    db = load_db()
    users = db.get("_users", {})

    if audience == "test":
        targets = [admin_user.id]
    else:
        # Collect unique numeric user_ids (skip web-only "w_..." entries)
        all_targets = []
        for uid_str, info in users.items():
            if uid_str.startswith("w_"):
                continue
            try:
                all_targets.append(int(uid_str))
            except (TypeError, ValueError):
                continue

        if audience == "active":
            # Filter to users who have any peer with handshake < 7 days
            try:
                dump = subprocess.run(
                    ["docker", "exec", CONTAINER, "awg", "show", "awg0", "dump"],
                    capture_output=True, text=True, timeout=5,
                ).stdout
                now_ts = time.time()
                active_pks = set()
                for line in dump.splitlines()[1:]:
                    cols = line.split("\t")
                    if len(cols) >= 7 and cols[4].isdigit():
                        if now_ts - int(cols[4]) < 7 * 86400:
                            active_pks.add(cols[0])
            except Exception:
                active_pks = set()

            active_uids = set()
            for uid_str, conns in db.items():
                if uid_str.startswith("_") or not isinstance(conns, list):
                    continue
                if any(c.get("pubkey") in active_pks for c in conns):
                    try:
                        active_uids.add(int(uid_str))
                    except (TypeError, ValueError):
                        pass
            targets = [t for t in all_targets if t in active_uids]
        else:  # 'all'
            targets = all_targets

    sent = 0
    failed = 0
    blocked = 0
    total = len(targets)

    audience_label = {"test": "тестовая (только мне)", "active": "активным", "all": "всем"}[audience]
    context.bot.send_message(
        chat_id=admin_user.id,
        text=f"📢 Начинаю рассылку ({audience_label}) для {total} пользователей...",
    )

    for tg_id in targets:
        try:
            context.bot.send_message(
                chat_id=tg_id,
                text=text,
                parse_mode="Markdown",
                disable_web_page_preview=True,
            )
            sent += 1
        except Exception as e:
            err = str(e).lower()
            if "blocked" in err or "deactivated" in err or "user is deactivated" in err or "chat not found" in err:
                blocked += 1
            else:
                failed += 1
            logger.warning(f"broadcast to {tg_id} failed: {e}")
        # Telegram limit ~30 msg/sec — keep well below
        time.sleep(0.05)

    report = (
        f"📢 *Рассылка завершена*\n\n"
        f"Всего: {total}\n"
        f"✅ Доставлено: {sent}\n"
        f"🚫 Заблокировали бота: {blocked}\n"
        f"❌ Ошибок: {failed}"
    )
    try:
        context.bot.send_message(chat_id=admin_user.id, text=report, parse_mode="Markdown")
    except Exception:
        context.bot.send_message(chat_id=admin_user.id, text=report.replace("*", ""))

    logger.info(f"BROADCAST by {tg_user_label(admin_user)}: total={total} sent={sent} blocked={blocked} failed={failed}")
    chat_log(admin_user, "broadcast", f"total={total} sent={sent} blocked={blocked} failed={failed}")


def cmd_broadcast(update: Update, context: CallbackContext):
    user = update.effective_user
    chat_log(user, "cmd_broadcast")
    if not is_admin(user.id):
        update.message.reply_text("Команда доступна только админам.")
        return
    _clear_states(user.id)
    AWAITING_BROADCAST.add(user.id)
    update.message.reply_text(
        "📢 *Рассылка всем пользователям*\n\n"
        "Отправьте текст следующим сообщением. Поддерживается Markdown.\n"
        "Для отмены отправьте /start",
        parse_mode="Markdown",
    )


# ── Text message router ────────────────────────────────────────────────

def _receive_my_domain(update: Update, context: CallbackContext, text: str):
    user = update.effective_user
    uid = str(user.id)
    ok, msg = ud.add_domain(USER_DOMAINS_FILE, uid, text, limit=MAX_DOMAINS_PER_USER)

    chat_log(user, "mydom_add", f"input={text!r} ok={ok}")

    if ok:
        # Attach a download button for the user's most-recent split-mode AWG peer
        db = load_db()
        user_conns = db.get(uid, [])
        awg_peers = [c for c in user_conns if c.get("type") == "awg" and c.get("tunnel") == "split"]
        awg_peers.sort(key=lambda c: c.get("created", ""), reverse=True)

        rows = []
        if awg_peers:
            latest = awg_peers[0]
            rows.append([InlineKeyboardButton(
                f"⬇️ Скачать {latest['name']} заново",
                callback_data=f"download_{latest['pubkey']}"
            )])
        rows.append([InlineKeyboardButton("⬅️ К доменам", callback_data="my_domains_menu")])

        update.message.reply_text(
            msg + "\n\n_Скачай конфиг заново, чтобы IPs попали в AllowedIPs._",
            reply_markup=InlineKeyboardMarkup(rows),
            parse_mode="Markdown",
        )
    else:
        rows = [
            [InlineKeyboardButton("🔄 Попробовать ещё", callback_data="mydom_add")],
            [InlineKeyboardButton("⬅️ К доменам", callback_data="my_domains_menu")],
        ]
        update.message.reply_text(msg, reply_markup=InlineKeyboardMarkup(rows), parse_mode="Markdown")


def _refresh_user_domains_job(context: CallbackContext):
    """PTB JobQueue callback — re-resolve every user's domains, DM on change.

    Scheduled every 6h (21600s). Skips entries refreshed in the last 6h
    to handle restart double-runs.
    """
    from datetime import datetime, timezone, timedelta

    bot_instance = context.bot
    now = datetime.now(timezone.utc)
    skip_if_fresh = timedelta(hours=6)

    refreshed = 0
    changed = 0
    users_to_notify = set()

    for uid, entry in list(ud.iter_all_entries(USER_DOMAINS_FILE)):
        try:
            resolved_at = datetime.strptime(
                entry.get("resolved_at", "1970-01-01T00:00:00Z"),
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            resolved_at = datetime.fromtimestamp(0, timezone.utc)
        if now - resolved_at < skip_if_fresh:
            continue

        v4, v6 = ud._resolve_domain(entry["domain"])
        time.sleep(0.1)  # rate cap ~10/sec
        refreshed += 1

        if not v4 and not v6:
            logger.warning(
                f"refresh_skip uid={uid} domain={entry['domain']} reason=no_ips"
            )
            continue

        old_v4 = set(entry.get("ips_v4") or [])
        old_v6 = set(entry.get("ips_v6") or [])
        if set(v4) != old_v4 or set(v6) != old_v6:
            ud.update_resolved_ips(USER_DOMAINS_FILE, uid, entry["domain"], v4, v6)
            changed += 1
            users_to_notify.add(uid)
            logger.info(
                f"refresh_change uid={uid} domain={entry['domain']} "
                f"v4_added={sorted(set(v4) - old_v4)} v4_removed={sorted(old_v4 - set(v4))}"
            )

    logger.info(
        f"refresh_summary refreshed={refreshed} changed={changed} "
        f"users_to_notify={len(users_to_notify)}"
    )

    for uid in users_to_notify:
        try:
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("🌐 Мои домены", callback_data="my_domains_menu")]
            ])
            bot_instance.send_message(
                chat_id=int(uid),
                text="🌐 Адреса твоих доменов обновились. Скачай конфиг заново, чтобы применить.",
                reply_markup=kb,
            )
        except Exception as e:
            # Most common: user blocked bot — telegram.error.Unauthorized / Forbidden
            logger.warning(f"notify_skipped uid={uid} reason={e!r}")


def handle_text(update: Update, context: CallbackContext):
    user = update.effective_user
    text = (update.message.text or "").strip()

    # User typing a custom domain for /my_domains
    if user.id in AWAITING_MY_DOMAIN:
        AWAITING_MY_DOMAIN.discard(user.id)
        _receive_my_domain(update, context, text)
        return

    # Admin typing a domain for the global /admin_domains list
    if user.id in AWAITING_ADMIN_DOMAIN:
        AWAITING_ADMIN_DOMAIN.discard(user.id)
        if not is_admin(user.id):
            return
        _receive_admin_domain(update, context, text)
        return

    # Admin replying to a support message
    if user.id in AWAITING_REPLY:
        target_uid = AWAITING_REPLY.pop(user.id)
        _handle_admin_reply(user.id, target_uid, text, context)
        return

    # Admin composing a broadcast
    if user.id in AWAITING_BROADCAST:
        AWAITING_BROADCAST.discard(user.id)
        audience = BROADCAST_AUDIENCE.pop(user.id, "all")
        if not is_admin(user.id):
            return
        _do_broadcast(user, text, context, audience=audience)
        show_main_menu(update, context)
        return

    # User sending support message
    if user.id in AWAITING_SUPPORT:
        AWAITING_SUPPORT.discard(user.id)
        sent = _handle_support_message(user, text, context)
        if sent and sent > 0:
            update.message.reply_text(f"✅ Сообщение доставлено ({sent} получателей). Ожидайте ответа.")
        else:
            update.message.reply_text("❌ Не удалось доставить сообщение администратору.")
        show_main_menu(update, context)
        return

    # User entering connection name
    if user.id in AWAITING_NAME:
        AWAITING_NAME.discard(user.id)
        raw_name = text
        name = re.sub(r'[^\w\-]', '', raw_name)[:30].strip()
        if not name:
            update.message.reply_text("Некорректное имя. Попробуйте снова (латиница, цифры, дефис).")
            AWAITING_NAME.add(user.id)
            return

        chosen_type = PENDING_TYPE.pop(user.id, "awg")
        chat_log(user, "name_input", f"type={chosen_type} name={name}")
        update.message.reply_text(f"⏳ Создаю подключение «{name}»...")
        safe_name = re.sub(r'[^\w\-]', '_', name)

        if chosen_type == "xray":
            json_file, client_uuid, err = create_xray_connection(user, name)
            if err:
                update.message.reply_text(f"❌ {err}")
                show_main_menu(update, context)
                return

            json_caption = (
                f"✅ XRay-подключение *{name}* создано!\n\n"
                "📦 *Формат XRay JSON* — со встроенными правилами маршрутизации\n\n"
                "📥 *Рекомендуемый клиент — Happ:*\n"
                "🍏 iPhone (иностр. App Store) — [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215)\n"
                "🍏 iPhone (рос. App Store) — [Happ](https://apps.apple.com/ru/app/happ-proxy-utility/id6504287215)\n"
                "📱 Android — [Happ (Google Play)](https://play.google.com/store/apps/details?id=com.happproxy)\n\n"
                "*Альтернативы:*\n"
                "🍏 iOS (иностр.) — [V2Box](https://apps.apple.com/app/v2box-v2ray-client/id6446814690), "
                "[Streisand](https://apps.apple.com/app/streisand/id6450534064), "
                "[FoXray](https://apps.apple.com/app/foxray/id6448898396)\n"
                "📱 Android — [v2rayNG](https://play.google.com/store/apps/details?id=com.v2ray.ang)\n\n"
                "Импорт: «Добавить конфиг» → «Из файла» → выбрать этот .json\n\n"
                "⚠️ *Для приложения Amnezia используйте обычное Amnezia-подключение* — "
                "XRay в Amnezia не применяет наши правила маршрутизации."
            )
            context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=json_file.encode("utf-8"),
                filename=f"kvn_{safe_name}.json",
                caption=json_caption,
                parse_mode="Markdown",
            )
            show_main_menu(update, context)
            return

        # AWG (split / full / youtube)
        mode_map = {"awg": "split", "clean": "full", "youtube": "youtube"}
        mode = mode_map.get(chosen_type, "split")
        config, err = create_connection(user, name, mode=mode)
        if err:
            update.message.reply_text(f"❌ {err}")
            show_main_menu(update, context)
            return

        if mode == "full":
            caption = (
                f"✅ Чистый конфиг *{name}* создан!\n\n"
                f"⚠️ *Весь трафик* идёт через сервер.\n"
                f"• Заблокированные сайты — работают\n"
                f"• YouTube/Instagram — работают\n"
                f"• Российские сервисы (банки, госуслуги, маркетплейсы) — могут блокировать вход т.к. видят иностранный IP. "
                f"Если это критично — выключите этот конфиг и пользуйтесь обычным Amnezia.\n\n"
                f"{INSTRUCTION_TEXT_CLEAN}"
            )
            filename = f"awg_clean_{safe_name}.conf"
        elif mode == "youtube":
            caption = (
                f"✅ YouTube-конфиг *{name}* создан!\n\n"
                f"🎬 Через сервер идёт только трафик Google/YouTube.\n"
                f"Всё остальное — напрямую. Можно держать включённым постоянно.\n\n"
                f"{INSTRUCTION_TEXT}"
            )
            filename = f"awg_youtube_{safe_name}.conf"
        else:
            caption = f"✅ Подключение *{name}* создано!\n\n{INSTRUCTION_TEXT}"
            filename = f"awg_{safe_name}.conf"

        context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=config.encode("utf-8"),
            filename=filename,
            caption=caption,
            parse_mode="Markdown",
        )
        show_main_menu(update, context)
        return

    # Unknown text — log and ignore
    chat_log(user, "message", text[:200])


# ── Web verification ────────────────────────────────────────────────────

WEB_USERS_FILE = Path(__file__).parent / "web_users.json"

def cmd_verify(update: Update, context: CallbackContext):
    """Handle /verify CODE — link web account to Telegram by code (not username)."""
    user = update.effective_user
    chat_log(user, "verify")

    if not context.args:
        update.message.reply_text("Использование: /verify XXXXXX\n(код из веб-панели)")
        return

    code = context.args[0].strip().upper()

    # Load web users
    try:
        with open(WEB_USERS_FILE, "r") as f:
            web_users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        web_users = {}

    # Find web account by verify_code (any login, not tied to username)
    found_login = None
    found_user = None
    for login, info in web_users.items():
        if info.get("verify_code", "").upper() == code and not info.get("verified"):
            found_login = login
            found_user = info
            break

    if not found_user:
        update.message.reply_text("❌ Неверный или уже использованный код.")
        return

    # Success — mark verified and link Telegram ID
    found_user["verified"] = True
    found_user["verified_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    found_user["tg_id"] = user.id

    # Migrate web-only connections to the real Telegram user ID
    db = load_db()
    save_user_info(db, user)
    web_uid = f"w_{found_login}"
    real_uid = str(user.id)
    if web_uid in db and web_uid != real_uid:
        existing = db.get(real_uid, [])
        existing.extend(db.pop(web_uid))
        db[real_uid] = existing
        # Also clean up _users entry for web-only
        db.get("_users", {}).pop(web_uid, None)

    save_db(db)

    with open(WEB_USERS_FILE, "w") as f:
        json.dump(web_users, f, indent=2, ensure_ascii=False)

    logger.info(f"VERIFY OK: login={found_login} tg_id={user.id}")
    chat_log(user, "verify_ok", f"login={found_login}")

    update.message.reply_text(
        f"✅ Telegram подтверждён!\n\n"
        f"Теперь вам доступно до {MAX_CONNECTIONS} подключений.\n"
        f"Обновите страницу веб-панели."
    )


# ── Cleanup unverified connections ──────────────────────────────────────

def cleanup_unverified():
    """Delete connections of unverified web users older than 30 minutes.
    Called periodically from the bot's job queue."""
    try:
        with open(WEB_USERS_FILE, "r") as f:
            web_users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return

    now = datetime.utcnow()
    db = load_db()
    banned_file = Path(__file__).parent / "banned.json"
    try:
        with open(banned_file) as f:
            banned = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        banned = []

    changed = False
    for username, info in list(web_users.items()):
        if info.get("verified"):
            continue

        registered = info.get("registered", "")
        if not registered:
            continue

        try:
            reg_time = datetime.strptime(registered, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

        if (now - reg_time).total_seconds() < 1800:  # 30 min
            continue

        # Time's up — find their connections
        # ONLY delete web-only accounts (w_ prefix), NEVER touch real bot users
        tg_uid = None
        is_real_bot_user = False
        for uid, uinfo in db.get("_users", {}).items():
            if uinfo.get("username", "").lower() == username and not uid.startswith("w_"):
                tg_uid = uid
                is_real_bot_user = True
                break

        # If this username belongs to a real bot user — just remove web_users entry, don't touch connections
        if is_real_bot_user:
            logger.info(f"CLEANUP: skipping @{username} — real bot user (uid={tg_uid})")
            del web_users[username]
            changed = True
            continue

        tg_uid = f"w_{username}"
        user_conns = db.get(tg_uid, [])
        if user_conns:
            for c in user_conns:
                try:
                    remove_peer_from_config(c["pubkey"])
                    update_clients_table(c["pubkey"], "", remove=True)
                except Exception as e:
                    logger.error(f"Cleanup error for {c.get('name')}: {e}")
            db[tg_uid] = []
            logger.info(f"CLEANUP: deleted {len(user_conns)} connections for unverified web user @{username}")
            changed = True

        # Increment strikes
        info["strikes"] = info.get("strikes", 0) + 1
        if info["strikes"] >= 2:
            if username not in banned:
                banned.append(username)
                logger.info(f"BANNED: @{username} (2 strikes)")
        # Remove from web_users so they can re-register (unless banned)
        del web_users[username]
        changed = True

    # Orphan-pass: w_* records in _users that have NO entry in web_users.json
    # (registration race / file corruption / manual edit). These never get
    # cleaned by the loop above. Catch them here.
    for uid in list(db.get("_users", {}).keys()):
        if not str(uid).startswith("w_"):
            continue
        username = str(uid)[2:].lower()
        if username in web_users:
            continue  # handled by the main loop above
        uinfo = db["_users"][uid]
        if uinfo.get("verified"):
            continue
        last = uinfo.get("last_seen") or uinfo.get("registered") or ""
        try:
            t = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if (now - t).total_seconds() < 1800:
            continue
        # Time's up — purge orphan
        for c in db.get(uid, []) or []:
            try:
                remove_peer_from_config(c["pubkey"])
                update_clients_table(c["pubkey"], "", remove=True)
            except Exception as e:
                logger.error(f"Orphan-cleanup error for {c.get('name')}: {e}")
        if uid in db:
            del db[uid]
        del db["_users"][uid]
        age_h = (now - t).total_seconds() / 3600
        logger.info(f"CLEANUP-ORPHAN: removed {uid} (no web_users.json entry, age {age_h:.1f}h)")
        changed = True

    if changed:
        save_db(db)
        with open(WEB_USERS_FILE, "w") as f:
            json.dump(web_users, f, indent=2, ensure_ascii=False)
        with open(banned_file, "w") as f:
            json.dump(banned, f, indent=2)


# ── Alert check (called from monitor or cron) ──────────────────────────

def send_admin_alert(bot, text):
    """Send alert to all admins."""
    for admin_id in ADMIN_IDS:
        try:
            bot.send_message(chat_id=admin_id, text=f"🚨 {text}", parse_mode="Markdown")
        except Exception as e:
            logger.error(f"Alert to {admin_id} failed: {e}")


# ── Main ────────────────────────────────────────────────────────────────

def main():
    install_bridge()  # tg_html: Markdown→HTML auto-bridge
    updater = Updater(BOT_TOKEN)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", cmd_start))
    dp.add_handler(CommandHandler("clients", cmd_clients))
    dp.add_handler(CallbackQueryHandler(cb_invite_create, pattern="^invite_create$"))
    dp.add_handler(CallbackQueryHandler(cb_invite_open, pattern="^invite_open$"))
    dp.add_handler(CallbackQueryHandler(cb_invite_open_uses, pattern=r"^invite_open_uses:"))
    dp.add_handler(CallbackQueryHandler(cb_invite_open_make, pattern=r"^invite_open_make:"))
    dp.add_handler(CallbackQueryHandler(cb_invite_open_list, pattern="^invite_open_list$"))
    dp.add_handler(CallbackQueryHandler(cb_invite_open_revoke, pattern=r"^invite_open_revoke:"))
    dp.add_handler(CallbackQueryHandler(cb_clients_view, pattern="^clients_view$"))
    dp.add_handler(CallbackQueryHandler(cb_bcast_send, pattern="^bcast_send:"))
    dp.add_handler(CallbackQueryHandler(cb_bcast_cancel, pattern="^bcast_cancel:"))
    dp.add_handler(CommandHandler("my_domains", cmd_my_domains))
    dp.add_handler(CallbackQueryHandler(cb_my_domains_menu, pattern="^my_domains_menu$"))
    dp.add_handler(CallbackQueryHandler(cb_mydom_add, pattern="^mydom_add$"))
    dp.add_handler(CallbackQueryHandler(cb_mydom_cancel, pattern="^mydom_cancel$"))
    dp.add_handler(CallbackQueryHandler(cb_mydom_remove, pattern="^mydom_remove$"))
    dp.add_handler(CallbackQueryHandler(cb_mydom_del, pattern=r"^mydom_del:"))
    dp.add_handler(CommandHandler("admin_domains", cmd_admin_domains))
    dp.add_handler(CallbackQueryHandler(cb_admindom_menu, pattern="^admindom_menu$"))
    dp.add_handler(CallbackQueryHandler(cb_admindom_add, pattern="^admindom_add$"))
    dp.add_handler(CallbackQueryHandler(cb_admindom_cancel, pattern="^admindom_cancel$"))
    dp.add_handler(CallbackQueryHandler(cb_admindom_remove, pattern="^admindom_remove$"))
    dp.add_handler(CallbackQueryHandler(cb_admindom_del, pattern=r"^admindom_del:"))
    dp.add_handler(CommandHandler("new", cmd_new))
    dp.add_handler(CommandHandler("my", cmd_my))
    dp.add_handler(CommandHandler("support", cmd_support))
    dp.add_handler(CommandHandler("verify", cmd_verify))
    dp.add_handler(CommandHandler("broadcast", cmd_broadcast))
    dp.add_handler(CallbackQueryHandler(button_handler))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_text))

    # Periodic cleanup of unverified web users (every 5 min)
    job_queue = updater.job_queue
    job_queue.run_repeating(lambda ctx: cleanup_unverified(), interval=300, first=60)

    # Periodic re-resolve of user /my_domains (every 6h; first run 2 min after startup)
    job_queue.run_repeating(_refresh_user_domains_job, interval=21600, first=120, name="refresh_user_domains")

    # Set bot commands menu
    try:
        updater.bot.set_my_commands([
            ("start", "Главное меню"),
            ("new", "Новое подключение"),
            ("my", "Мои подключения"),
            ("support", "Написать админу"),
            ("verify", "Подтвердить аккаунт (код с сайта)"),
        ])
    except Exception as e:
        logger.warning(f"set_my_commands failed: {e}")


        # Admin-scoped commands (shown only in CLIENTS_VIEW_IDS chats)
        try:
            from telegram import BotCommand, BotCommandScopeChat
            admin_cmds = [
                BotCommand("start", "Главное меню"),
                BotCommand("new", "Новое подключение"),
                BotCommand("my", "Мои подключения"),
                BotCommand("support", "Написать админу"),
                BotCommand("verify", "Подтвердить аккаунт (код с сайта)"),
                BotCommand("clients", "Клиенты бота (админ)"),
            ]
            for admin_id in CLIENTS_VIEW_IDS:
                updater.bot.set_my_commands(admin_cmds, scope=BotCommandScopeChat(chat_id=admin_id))
        except Exception as e:
            logger.warning(f"scoped set_my_commands failed: {e}")


    # Bootstrap invites allowlist from existing users_db
    try:
        _existing = list(load_db().keys())
        invites.bootstrap_from(_existing, admin_ids=list(ADMIN_IDS))
        for _aid in ADMIN_IDS:
            invites.ensure_allowed(_aid, mark_admin=True)
    except Exception as _e:
        logger.warning(f"invites bootstrap failed: {_e}")

    logger.info("Bot started")
    updater.start_polling()
    updater.idle()


if __name__ == "__main__":
    main()
