"""
Telegram bot for Amnezia Web Panel.
Uses raw Telegram Bot API via httpx — no library version conflicts.
Runs as a background asyncio task alongside the FastAPI app.

Capabilities are injected via a `services` dict (see app.bot_services()):
    load_data, generate_vpn_link, register_user_with_code,
    create_user_connection, get_client_config, create_invite_codes
This lets friends self-register with an invite code and provision their own
per-server / per-protocol / per-device configs without admin involvement.
"""
import asyncio
import html
import logging
from typing import Optional, Callable

import httpx

logger = logging.getLogger(__name__)
# Avoid leaking Telegram bot tokens in access logs: httpx logs request URLs
# at INFO level, and Bot API URLs include the token in the path.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# ----------------------------------------------------------------------- #
#  Global state
# ----------------------------------------------------------------------- #
_bot_task: Optional[asyncio.Task] = None

# Live reference to the running bot's API client, set while _run_bot is active.
# Lets the panel push broadcasts through the already-authenticated client; when
# the bot isn't polling we fall back to an ephemeral client built from the token.
_bot_api: "Optional[TelegramAPI]" = None

# Per-chat conversation state (single-process bot, in-memory is fine).
# tg_id -> {"action": "await_code" | "await_name", "server_id": int, "protocol": str}
_pending: dict = {}

# Protocols we never expose for self-service config generation (not VPN tunnels).
_NON_VPN_PROTOCOLS = {"dns", "adguard"}

# Pretty labels for protocol keys.
_PROTO_LABELS = {
    "awg": "AmneziaWG",
    "awg2": "AmneziaWG 2",
    "awg_legacy": "AmneziaWG (legacy)",
    "xray": "XRay / VLESS",
    "telemt": "Telemt (Telegram)",
    "wireguard": "WireGuard",
    "socks5": "SOCKS5",
}


def is_running() -> bool:
    return _bot_task is not None and not _bot_task.done()


def launch_bot(token: str, services: dict):
    global _bot_task
    _bot_task = asyncio.create_task(
        _run_bot(token, services),
        name="telegram_bot",
    )
    return _bot_task


async def stop_bot():
    global _bot_task
    if _bot_task and not _bot_task.done():
        _bot_task.cancel()
        try:
            await _bot_task
        except asyncio.CancelledError:
            pass
        _bot_task = None
        logger.info("Telegram bot stopped.")


# ----------------------------------------------------------------------- #
#  Low-level Telegram API helpers
# ----------------------------------------------------------------------- #
class TelegramAPI:
    def __init__(self, token: str, client: httpx.AsyncClient):
        self.base = f"https://api.telegram.org/bot{token}"
        self.client = client

    async def call(self, method: str, **params) -> dict:
        r = await self.client.post(f"{self.base}/{method}", json=params, timeout=30)
        return r.json()

    async def get_updates(self, offset: int = 0, timeout: int = 25) -> list:
        r = await self.client.post(
            f"{self.base}/getUpdates",
            json={"offset": offset, "timeout": timeout, "allowed_updates": ["message", "callback_query"]},
            timeout=timeout + 10,
        )
        data = r.json()
        if data.get("ok"):
            return data["result"]
        return []

    async def send_message(self, chat_id, text: str, reply_markup=None, parse_mode="HTML") -> dict:
        import json
        params = {"chat_id": chat_id, "text": text}
        if parse_mode:
            params["parse_mode"] = parse_mode
        if reply_markup:
            params["reply_markup"] = json.dumps(reply_markup)
        return (await self.call("sendMessage", **params))

    async def edit_message(self, chat_id, message_id, text: str, reply_markup=None, parse_mode="HTML"):
        import json
        params = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": parse_mode}
        if reply_markup:
            params["reply_markup"] = json.dumps(reply_markup)
        await self.call("editMessageText", **params)

    async def answer_callback(self, callback_query_id: str, text: str = ""):
        await self.call("answerCallbackQuery", callback_query_id=callback_query_id, text=text)

    async def send_document(self, chat_id, filename: str, content: bytes, caption: str = ""):
        files = {"document": (filename, content, "text/plain")}
        data = {"chat_id": str(chat_id), "caption": caption}
        r = await self.client.post(f"{self.base}/sendDocument", data=data, files=files, timeout=30)
        return r.json()


# ----------------------------------------------------------------------- #
#  Helpers
# ----------------------------------------------------------------------- #
def _find_user(load_data_fn: Callable, tg_id: str, services: dict = None):
    data = load_data_fn()
    tg_id_clean = str(tg_id).lstrip("@")
    for u in data.get("users", []):
        stored = str(u.get("telegramId", "") or "").lstrip("@")
        if stored and stored == tg_id_clean:
            if services:
                fn = services.get("record_bot_activity")
                if fn:
                    try:
                        fn(tg_id_clean)
                    except Exception:
                        pass
            return u
    return None


# ----------------------------------------------------------------------- #
#  Broadcast / notifications
# ----------------------------------------------------------------------- #
def _recipient_ids(load_data_fn: Callable, audience: str = "all") -> list:
    """Telegram chat IDs to notify. `audience`: 'all' registered & enabled users,
    or 'admins' for admin accounts only. Deduplicated, order-preserving."""
    data = load_data_fn()
    out, seen = [], set()
    for u in data.get("users", []):
        if not u.get("enabled", True):
            continue
        if audience == "admins" and u.get("role") != "admin":
            continue
        tg = str(u.get("telegramId", "") or "").lstrip("@")
        if tg and tg not in seen:
            seen.add(tg)
            out.append(tg)
    return out


def _as_chat_id(value: str):
    """Telegram numeric IDs must be ints; @usernames stay as '@name' strings."""
    v = str(value)
    if v.lstrip("-").isdigit():
        return int(v)
    return v if v.startswith("@") else f"@{v}"


async def _send_broadcast(api: "TelegramAPI", recipient_ids: list, text: str, parse_mode=None) -> dict:
    """Deliver `text` to each chat id, tolerating blocks/limits. Telegram caps
    bulk sends ~30/s, so we pace lightly and honour 429 retry_after once."""
    sent = blocked = failed = 0
    for cid in recipient_ids:
        try:
            resp = await api.send_message(_as_chat_id(cid), text, parse_mode=parse_mode)
            if resp.get("ok"):
                sent += 1
            else:
                code = resp.get("error_code")
                if code == 429:
                    retry = resp.get("parameters", {}).get("retry_after", 1)
                    await asyncio.sleep(retry + 0.5)
                    resp2 = await api.send_message(_as_chat_id(cid), text, parse_mode=parse_mode)
                    if resp2.get("ok"):
                        sent += 1
                    else:
                        failed += 1
                elif code == 403:  # user blocked / never started the bot
                    blocked += 1
                else:
                    failed += 1
                    logger.warning(f"broadcast to {cid} failed: {resp}")
        except Exception as e:
            failed += 1
            logger.warning(f"broadcast to {cid} error: {e}")
        await asyncio.sleep(0.05)
    return {"sent": sent, "blocked": blocked, "failed": failed, "total": len(recipient_ids)}


async def broadcast_message(services: dict, text: str, audience: str = "all", parse_mode=None) -> dict:
    """Send a ready-made message to users. Uses the live bot client if polling,
    otherwise opens a short-lived client from the saved token."""
    load_data_fn = services["load_data"]
    data = load_data_fn()
    token = data.get("settings", {}).get("telegram", {}).get("token", "")
    if not token:
        return {"error": "telegram token not set", "sent": 0, "total": 0}

    ids = _recipient_ids(load_data_fn, audience)
    if not ids:
        return {"sent": 0, "blocked": 0, "failed": 0, "total": 0}

    if _bot_api is not None:
        return await _send_broadcast(_bot_api, ids, text, parse_mode)

    async with httpx.AsyncClient() as client:
        api = TelegramAPI(token, client)
        return await _send_broadcast(api, ids, text, parse_mode)


async def broadcast_custom(services: dict, raw_text: str, audience: str = "all") -> dict:
    """Admin-authored announcement. Body is HTML-escaped so arbitrary text can't
    break Telegram parsing, then wrapped with a recognizable header."""
    body = html.escape((raw_text or "").strip())
    if not body:
        return {"error": "empty text", "sent": 0, "total": 0}
    text = f"📢 <b>Объявление</b>\n\n{body}"
    return await broadcast_message(services, text, audience=audience, parse_mode="HTML")


async def _notify_infra(services: dict, text: str) -> None:
    """Send an infrastructure notice to all users if the server_events toggle is
    on. Fire-and-forget: never raises into the caller."""
    try:
        data = services["load_data"]()
        notif = data.get("settings", {}).get("notifications", {})
        if not notif.get("server_events", True):
            return
        await broadcast_message(services, text, audience="all", parse_mode="HTML")
    except Exception as e:
        logger.warning(f"_notify_infra failed: {e}")


async def notify_server_event(services: dict, kind: str, server_name: str) -> None:
    """Notice about a server being added/removed."""
    name = html.escape(server_name or "сервер")
    if kind == "added":
        text = (
            f"🆕 <b>Новый сервер доступен:</b> {name}\n\n"
            "Открой ➕ «Новое устройство / конфиг», чтобы создать конфиг."
        )
    elif kind == "removed":
        text = (
            f"🗑 <b>Сервер отключён:</b> {name}\n\n"
            "Конфиги на этом сервере больше не работают — при необходимости создай новый на другом сервере."
        )
    else:
        return
    await _notify_infra(services, text)


async def notify_protocol_event(services: dict, kind: str, server_name: str, protocol: str) -> None:
    """Notice about a protocol being installed/removed on a server. Infra-only
    protocols (DNS/AdGuard) are skipped — users can't make configs for them."""
    if protocol in _NON_VPN_PROTOCOLS:
        return
    name = html.escape(server_name or "сервер")
    proto = html.escape(_proto_label(protocol))
    if kind == "installed":
        text = (
            f"➕ <b>Новый протокол:</b> {proto}\n"
            f"Сервер: {name}\n\n"
            "Можешь создать конфиг через ➕ «Новое устройство / конфиг»."
        )
    elif kind == "removed":
        text = (
            f"➖ <b>Протокол отключён:</b> {proto}\n"
            f"Сервер: {name}\n\n"
            "Конфиги этого протокола на сервере больше не работают."
        )
    else:
        return
    await _notify_infra(services, text)


async def notify_server_availability(
    services: dict,
    kind: str,
    server_name: str,
    host: str,
    port: int,
    detail=None,
) -> None:
    """Admin-only alert about host reachability (TCP to SSH port). Independent
    of the server_events toggle that broadcasts inventory changes to everyone."""
    name = html.escape(server_name or host or "сервер")
    endpoint = html.escape(f"{host}:{port}")
    if kind == "down":
        text = (
            f"🔴 <b>Сервер недоступен:</b> {name}\n"
            f"<code>{endpoint}</code>\n"
            "SSH-порт не отвечает."
        )
    elif kind == "up":
        latency = ""
        if detail is not None:
            latency = f"\n~{html.escape(str(detail))} ms"
        text = (
            f"🟢 <b>Сервер снова доступен:</b> {name}\n"
            f"<code>{endpoint}</code>{latency}"
        )
    else:
        return
    try:
        await broadcast_message(services, text, audience="admins", parse_mode="HTML")
    except Exception as e:
        logger.warning(f"notify_server_availability failed: {e}")


def _proto_label(proto: str) -> str:
    return _PROTO_LABELS.get(proto, proto.upper())


def _server_label(server: dict) -> str:
    return server.get("name") or server.get("host", "Unknown")


def _telemt_apply_url(config: str) -> Optional[str]:
    """Convert a tg://proxy?... link into the https://t.me/proxy?... form.

    The t.me form is a valid inline-button URL and, when tapped inside
    Telegram, opens the native "Connect proxy?" dialog — acting as an
    "Apply" button. Returns None if the config isn't a proxy link."""
    if not config:
        return None
    c = config.strip()
    marker = "proxy?"
    idx = c.find(marker)
    if idx == -1:
        return None
    query = c[idx + len(marker):]
    if not query:
        return None
    return f"https://t.me/proxy?{query}"


def _main_menu_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": "➕ Новое устройство / конфиг", "callback_data": "new"}],
            [{"text": "📂 Мои конфиги", "callback_data": "mine"}],
            [{"text": "📊 Статус серверов", "callback_data": "status"}],
            [{"text": "ℹ️ Помощь", "callback_data": "help"}],
        ]
    }


def _build_connections_keyboard(conns: list, data: dict) -> dict:
    """Build inline keyboard where each button = one connection."""
    rows = []
    servers = data.get("servers", [])
    for c in conns:
        sid = c.get("server_id", 0)
        server_name = "Unknown"
        if sid < len(servers):
            server_name = _server_label(servers[sid])[:20]
        proto = _proto_label(c.get("protocol", ""))
        name = c.get("name", "Connection")
        label = f"🔐 {name} · {proto} · {server_name}"
        rows.append([{"text": label, "callback_data": f"cfg:{c['id']}"}])
    rows.append([{"text": "🔄 Обновить", "callback_data": "mine"}])
    rows.append([{"text": "⬅️ Меню", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


# ----------------------------------------------------------------------- #
#  Registration
# ----------------------------------------------------------------------- #
_REG_ERRORS = {
    "not_found": "❌ Код не найден. Проверь и попробуй ещё раз.",
    "disabled": "❌ Этот код отключён.",
    "expired": "❌ Срок действия кода истёк.",
    "exhausted": "❌ Код уже использован максимальное число раз.",
}


def _welcome_text(first_name: str) -> str:
    name = first_name or "друг"
    return (
        f"👋 Привет, <b>{name}</b>!\n\n"
        "Это бот для доступа к личному VPN. Здесь ты сам создаёшь конфиги "
        "для своих устройств.\n\n"
        "🔑 Чтобы начать, пришли свой <b>код регистрации</b> одним сообщением "
        "(или командой <code>/register КОД</code>).\n\n"
        "ℹ️ <b>Важно:</b>\n"
        "• Один пользователь — один код. Код одноразовый и привязывается к тебе.\n"
        "• Один конфиг — одно устройство. Для каждого телефона/ноутбука создавай отдельный конфиг."
    )


# Short, user-facing protocol blurbs. Keyed by the canonical protocol group
# (awg variants collapse into one "awg" entry). Order here = display order.
_PROTO_HELP = {
    "awg": "<b>AmneziaWG</b> — основной. Маскируется под обычный трафик, обходит "
           "блокировки, работает на всех устройствах (iPhone/Mac/Android/Windows). "
           "Нужен клиент AmneziaWG или AmneziaVPN.",
    "xray": "<b>XRay / VLESS</b> — запасной, если AmneziaWG не подключается в жёсткой сети.",
    "telemt": "<b>Telemt</b> — прокси только для Telegram (не VPN). Разблокирует сам "
              "мессенджер: нажми «Применить».",
    "wireguard": "<b>WireGuard</b> — классический WG: быстрый, но маскируется слабее AWG.",
    "socks5": "<b>SOCKS5</b> — лёгкий прокси для отдельного приложения или браузера.",
}


def _available_protocols(load_data_fn: Callable) -> list:
    """Canonical protocol groups actually installed across the fleet, in
    _PROTO_HELP display order. AWG variants collapse into one 'awg' entry."""
    present = set()
    try:
        for srv in load_data_fn().get("servers", []):
            for p in (srv.get("protocols") or {}):
                if p in ("awg", "awg2", "awg_legacy"):
                    present.add("awg")
                elif p in _PROTO_HELP:
                    present.add(p)
    except Exception as e:
        logger.warning(f"_available_protocols failed: {e}")
    return [p for p in _PROTO_HELP if p in present]


def _help_text(username: Optional[str] = None, services: Optional[dict] = None) -> str:
    intro = "✅ Ты в системе.\n\n"
    if username:
        intro = f"✅ Ты в системе как <b>{username}</b>.\n\n"
    text = (
        intro +
        "Как пользоваться:\n"
        "➕ «Новое устройство / конфиг» — создать конфиг (сервер → протокол → имя).\n"
        "📂 «Мои конфиги» — список твоих конфигов и их выдача.\n"
        "📊 «Статус серверов» — доступность и пинг.\n"
    )
    if services and services.get("load_data"):
        keys = _available_protocols(services["load_data"])
        if keys:
            text += "\n🔌 <b>Протоколы — что выбрать:</b>\n"
            text += "\n".join(f"• {_PROTO_HELP[k]}" for k in keys) + "\n"
    text += (
        "\n⚠️ Помни: <b>один конфиг = одно устройство</b>. "
        "Не передавай свои конфиги другим — у каждого должен быть свой код."
    )
    return text


async def _show_welcome_for_new(api: TelegramAPI, chat_id: int, tg_id: str, first_name: str):
    _pending[tg_id] = {"action": "await_code"}
    await api.send_message(chat_id, _welcome_text(first_name))


async def _try_register(api: TelegramAPI, chat_id: int, tg_id: str, first_name: str, code: str, services: dict):
    register_fn = services["register_user_with_code"]
    res = await asyncio.to_thread(register_fn, code, tg_id, first_name)
    if res.get("error") == "already_registered":
        _pending.pop(tg_id, None)
        await api.send_message(chat_id, "✅ Ты уже зарегистрирован. Открываю меню.", reply_markup=_main_menu_keyboard())
        return
    if "error" in res:
        await api.send_message(chat_id, _REG_ERRORS.get(res["error"], f"❌ Ошибка: {res['error']}"))
        return
    _pending.pop(tg_id, None)
    fn = services.get("record_bot_activity")
    if fn:
        try:
            await asyncio.to_thread(fn, tg_id)
        except Exception:
            pass
    await api.send_message(
        chat_id,
        f"🎉 Регистрация прошла успешно!\n"
        f"Твой логин в системе: <b>{res.get('username')}</b>.\n\n"
        + _help_text(services=services),
        reply_markup=_main_menu_keyboard(),
    )


# ----------------------------------------------------------------------- #
#  /start handler
# ----------------------------------------------------------------------- #
async def _handle_start(api: TelegramAPI, msg: dict, services: dict):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    first_name = msg["from"].get("first_name", "")
    text = msg.get("text", "") or ""

    # /start <payload> — deep-link may carry an invite code
    payload = ""
    parts = text.split(maxsplit=1)
    if len(parts) > 1:
        payload = parts[1].strip()

    panel_user = _find_user(services["load_data"], tg_id, services)

    if not panel_user:
        if payload:
            await _try_register(api, chat_id, tg_id, first_name, payload, services)
        else:
            await _show_welcome_for_new(api, chat_id, tg_id, first_name)
        return

    await api.send_message(
        chat_id,
        f"👋 Привет, <b>{first_name}</b>!\n"
        f"Ты в системе как <b>{panel_user['username']}</b>.\n\n"
        "Выбери действие:",
        reply_markup=_main_menu_keyboard(),
    )


async def _show_menu(api: TelegramAPI, chat_id: int, message_id: Optional[int], tg_id: str, services: dict):
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await _show_welcome_for_new(api, chat_id, tg_id, "")
        return
    text = f"Ты в системе как <b>{panel_user['username']}</b>.\n\nВыбери действие:"
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=_main_menu_keyboard())
    else:
        await api.send_message(chat_id, text, reply_markup=_main_menu_keyboard())


async def _show_help(api: TelegramAPI, chat_id: int, message_id: Optional[int], tg_id: str, services: dict):
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await _show_welcome_for_new(api, chat_id, tg_id, "")
        return
    text = _help_text(panel_user.get("username"), services=services)
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=_main_menu_keyboard())
    else:
        await api.send_message(chat_id, text, reply_markup=_main_menu_keyboard())


# ----------------------------------------------------------------------- #
#  New device flow: choose server -> protocol -> name
# ----------------------------------------------------------------------- #
async def _show_servers(api: TelegramAPI, chat_id: int, message_id: int, services: dict):
    data = services["load_data"]()
    servers = data.get("servers", [])
    rows = []
    for idx, srv in enumerate(servers):
        installed = [p for p in srv.get("protocols", {}).keys() if p not in _NON_VPN_PROTOCOLS]
        if not installed:
            continue
        rows.append([{"text": f"🌐 {_server_label(srv)}", "callback_data": f"srv:{idx}"}])
    rows.append([{"text": "⬅️ Меню", "callback_data": "menu"}])
    if len(rows) == 1:
        await api.edit_message(chat_id, message_id, "Пока нет доступных серверов. Обратись к администратору.",
                               reply_markup={"inline_keyboard": rows})
        return
    await api.edit_message(chat_id, message_id, "Выбери <b>сервер</b>:", reply_markup={"inline_keyboard": rows})


async def _show_protocols(api: TelegramAPI, chat_id: int, message_id: int, server_id: int, services: dict):
    data = services["load_data"]()
    servers = data.get("servers", [])
    if server_id >= len(servers):
        await api.edit_message(chat_id, message_id, "❌ Сервер не найден.", reply_markup=_main_menu_keyboard())
        return
    server = servers[server_id]
    rows = []
    for proto in server.get("protocols", {}).keys():
        if proto in _NON_VPN_PROTOCOLS:
            continue
        rows.append([{"text": f"🔌 {_proto_label(proto)}", "callback_data": f"proto:{server_id}:{proto}"}])
    rows.append([{"text": "⬅️ Назад к серверам", "callback_data": "new"}])
    if len(rows) == 1:
        await api.edit_message(chat_id, message_id, "На этом сервере нет доступных протоколов.",
                               reply_markup={"inline_keyboard": rows})
        return
    await api.edit_message(
        chat_id, message_id,
        f"Сервер: <b>{_server_label(server)}</b>\nВыбери <b>протокол</b>:",
        reply_markup={"inline_keyboard": rows},
    )


async def _ask_device_name(api: TelegramAPI, chat_id: int, message_id: int, tg_id: str, server_id: int, proto: str, services: dict):
    data = services["load_data"]()
    servers = data.get("servers", [])
    server = servers[server_id] if server_id < len(servers) else {}
    _pending[tg_id] = {"action": "await_name", "server_id": server_id, "protocol": proto}
    await api.edit_message(
        chat_id, message_id,
        f"Сервер: <b>{_server_label(server)}</b>\n"
        f"Протокол: <b>{_proto_label(proto)}</b>\n\n"
        "✍️ <b>Пришли своё название устройства</b> (например <i>iPhone</i> или <i>Ноутбук</i>),\n"
        "либо нажми «🎲 Авто-имя» — сгенерирую автоматически.\n\n"
        "<i>Имя будет сделано уникальным автоматически.</i>",
        reply_markup={"inline_keyboard": [
            [{"text": "🎲 Авто-имя", "callback_data": f"auto:{server_id}:{proto}"}],
            [{"text": "⬅️ Меню", "callback_data": "menu"}],
        ]},
    )


async def _create_and_send(api: TelegramAPI, chat_id: int, tg_id: str, server_id: int, proto: str, name: str, services: dict):
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await api.send_message(chat_id, "❌ Доступ запрещён. Зарегистрируйся: /start")
        return

    loading = await api.send_message(chat_id, f"⏳ Создаю конфиг <b>{name}</b>…")
    loading_id = loading.get("result", {}).get("message_id")

    create_fn = services["create_user_connection"]
    try:
        res = await asyncio.to_thread(create_fn, panel_user["id"], server_id, proto, name)
    except Exception as e:
        logger.exception("Bot: error creating connection")
        res = {"error": str(e)}

    if "error" in res:
        msg = {
            "protocol_not_installed": "❌ Этот протокол не установлен на сервере.",
            "server_not_found": "❌ Сервер не найден.",
            "user_not_found": "❌ Профиль не найден. Зарегистрируйся заново: /start",
            "create_failed": "❌ Не удалось создать клиента на сервере.",
        }.get(res["error"], f"❌ Не удалось создать конфиг.\n<code>{res['error']}</code>")
        if loading_id:
            await api.edit_message(chat_id, loading_id, msg, reply_markup=_main_menu_keyboard())
        else:
            await api.send_message(chat_id, msg, reply_markup=_main_menu_keyboard())
        return

    if loading_id:
        await api.call("deleteMessage", chat_id=chat_id, message_id=loading_id)

    data = services["load_data"]()
    servers = data.get("servers", [])
    server = servers[server_id] if server_id < len(servers) else {}
    await _send_config(api, chat_id, name, server, proto, res.get("config", ""))
    await api.send_message(chat_id, "Готово. Создать ещё или открыть список?", reply_markup=_main_menu_keyboard())


# ----------------------------------------------------------------------- #
#  Existing connections
# ----------------------------------------------------------------------- #
async def _show_my_connections(api: TelegramAPI, chat_id: int, message_id: Optional[int], tg_id: str, services: dict):
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await _show_welcome_for_new(api, chat_id, tg_id, "")
        return
    data = services["load_data"]()
    conns = [c for c in data.get("user_connections", []) if c["user_id"] == panel_user["id"]]
    if not conns:
        text = "У тебя пока нет конфигов. Нажми «Новое устройство», чтобы создать первый."
        kb = _main_menu_keyboard()
    else:
        text = f"<b>Твои конфиги</b> ({len(conns)}) — нажми, чтобы получить:"
        kb = _build_connections_keyboard(conns, data)
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=kb)
    else:
        await api.send_message(chat_id, text, reply_markup=kb)


async def _handle_get_existing_config(api: TelegramAPI, chat_id: int, callback_id: str, conn_id: str, tg_id: str, services: dict):
    await api.answer_callback(callback_id, "Получаю конфиг…")
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await api.send_message(chat_id, "❌ Доступ запрещён.")
        return
    data = services["load_data"]()
    conn = next(
        (c for c in data.get("user_connections", [])
         if c["id"] == conn_id and c["user_id"] == panel_user["id"]),
        None,
    )
    if not conn:
        await api.send_message(chat_id, "❌ Конфиг не найден.")
        return
    servers = data.get("servers", [])
    sid = conn["server_id"]
    if sid >= len(servers):
        await api.send_message(chat_id, "❌ Сервер не найден.")
        return
    server = servers[sid]
    proto = conn.get("protocol", "awg")
    name = conn.get("name", "Connection")

    loading = await api.send_message(chat_id, f"⏳ Получаю конфиг <b>{name}</b>…")
    loading_id = loading.get("result", {}).get("message_id")
    try:
        config = await asyncio.to_thread(services["get_client_config"], conn)
    except Exception as e:
        logger.exception("Bot: error getting existing config")
        if loading_id:
            await api.edit_message(chat_id, loading_id, f"❌ Ошибка: {e}")
        return
    if not config:
        if loading_id:
            await api.edit_message(chat_id, loading_id, "❌ Не удалось получить конфигурацию.")
        return
    if loading_id:
        await api.call("deleteMessage", chat_id=chat_id, message_id=loading_id)
    await _send_config(api, chat_id, name, server, proto, config)
    # Per-config management card: delete lives here (keeps the list single-column).
    await api.send_message(
        chat_id,
        f"⚙️ Управление конфигом «<b>{html.escape(name)}</b>»:",
        reply_markup={"inline_keyboard": [
            [{"text": "🗑 Удалить это подключение", "callback_data": f"del:{conn_id}"}],
            [{"text": "⬅️ К списку", "callback_data": "mine"}],
        ]},
    )


async def _confirm_delete(api: TelegramAPI, chat_id: int, callback_id: str, message_id: Optional[int], conn_id: str, tg_id: str, services: dict):
    """Step 1: ask the user to confirm deleting one of their own connections."""
    await api.answer_callback(callback_id)
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await api.send_message(chat_id, "❌ Доступ запрещён.")
        return
    data = services["load_data"]()
    conn = next(
        (c for c in data.get("user_connections", [])
         if c["id"] == conn_id and c["user_id"] == panel_user["id"]),
        None,
    )
    if not conn:
        await _show_my_connections(api, chat_id, message_id, tg_id, services)
        return
    name = html.escape(conn.get("name", "конфиг"))
    kb = {"inline_keyboard": [[
        {"text": "✅ Да, удалить", "callback_data": f"delok:{conn_id}"},
        {"text": "↩️ Отмена", "callback_data": "mine"},
    ]]}
    text = (
        f"🗑 Удалить «<b>{name}</b>»?\n\n"
        "Устройство перестанет подключаться к VPN. Действие необратимо."
    )
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=kb)
    else:
        await api.send_message(chat_id, text, reply_markup=kb)


async def _do_delete(api: TelegramAPI, chat_id: int, callback_id: str, message_id: Optional[int], conn_id: str, tg_id: str, services: dict):
    """Step 2: actually remove the peer on the server and drop the record."""
    await api.answer_callback(callback_id, "Удаляю…")
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await api.send_message(chat_id, "❌ Доступ запрещён.")
        return
    delete_fn = services.get("delete_user_connection")
    if not delete_fn:
        await api.send_message(chat_id, "❌ Удаление сейчас недоступно.")
        return
    res = await asyncio.to_thread(delete_fn, panel_user["id"], conn_id)
    if res.get("error"):
        msg = {
            "not_found": "Конфиг не найден.",
            "forbidden": "Это не твой конфиг.",
            "server_error": "Сервер недоступен, попробуй позже.",
        }.get(res["error"], f"Ошибка: {res['error']}")
        await api.send_message(chat_id, f"❌ {msg}")
        await _show_my_connections(api, chat_id, message_id, tg_id, services)
        return
    await _show_my_connections(api, chat_id, message_id, tg_id, services)
    deleted = html.escape(res.get("name", "") or "конфиг")
    await api.send_message(chat_id, f"🗑 Готово, «<b>{deleted}</b>» удалён.")


# ----------------------------------------------------------------------- #
#  Server status
# ----------------------------------------------------------------------- #
async def _show_status(api: TelegramAPI, chat_id: int, message_id: Optional[int], tg_id: str, services: dict):
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user:
        await _show_welcome_for_new(api, chat_id, tg_id, "")
        return

    get_status = services.get("get_servers_status")
    statuses = await asyncio.to_thread(get_status) if get_status else []

    if not statuses:
        text = "Серверов пока нет."
    else:
        online_n = sum(1 for s in statuses if s.get("online"))
        header = f"<b>📊 Статус серверов</b> · {online_n}/{len(statuses)} онлайн"
        blocks = []
        for s in statuses:
            name = html.escape(str(s.get("name", "—")))
            if s.get("online"):
                ping = s.get("ping_ms")
                ping_txt = f"{ping} ms" if ping is not None else "—"
                icon = "🟢" if (ping is None or ping < 200) else "🟡"
                head = f"{icon} <b>{name}</b> — {ping_txt}"
            else:
                head = f"🔴 <b>{name}</b> — недоступен"
            protos = " · ".join(
                html.escape(_proto_label(p))
                for p in s.get("protocols", []) if p not in _NON_VPN_PROTOCOLS
            )
            block = head + (f"\n   <i>{protos}</i>" if protos else "")
            blocks.append(block)
        # Blank line between servers ("воздух") for readability.
        text = header + "\n\n" + "\n\n".join(blocks)

    kb = {"inline_keyboard": [
        [{"text": "🔄 Обновить", "callback_data": "status"}],
        [{"text": "⬅️ Меню", "callback_data": "menu"}],
    ]}
    if message_id:
        await api.edit_message(chat_id, message_id, text, reply_markup=kb)
    else:
        await api.send_message(chat_id, text, reply_markup=kb)


# ----------------------------------------------------------------------- #
#  Shared config sender
# ----------------------------------------------------------------------- #
async def _send_config(api: TelegramAPI, chat_id: int, name: str, server: dict, proto: str, config: str):
    server_name = _server_label(server)
    await api.send_message(
        chat_id,
        f"✅ <b>{name}</b>\n"
        f"🌐 Сервер: <b>{server_name}</b>\n"
        f"🔌 Протокол: <b>{_proto_label(proto)}</b>",
    )

    if proto == "telemt":
        # config is a tg://proxy?server=...&port=...&secret=... link.
        # The https://t.me/proxy?... form opens Telegram's native
        # "Connect proxy?" dialog when tapped — i.e. an "Apply" button.
        apply_url = _telemt_apply_url(config)
        kb = None
        if apply_url:
            kb = {"inline_keyboard": [[{"text": "✅ Применить (подключить в Telegram)", "url": apply_url}]]}
        await api.send_message(
            chat_id,
            "🔗 <b>Прокси для Telegram</b>\n\n"
            "• Нажми <b>«Применить»</b> — Telegram сам предложит подключить прокси.\n"
            "• Или скопируй ссылку вручную (нажми на неё):\n"
            f"<code>{config}</code>",
            reply_markup=kb,
        )
        return

    if proto == "xray":
        await api.send_message(chat_id, f"🔗 <b>Ссылка для подключения</b> (нажми, чтобы скопировать):\n<code>{config}</code>")
        return

    # AWG / WireGuard — отдаём ТОЛЬКО «Оригинальный формат AmneziaWG» (.conf).
    # Это нативный WireGuard-конфиг с параметрами J/S1-S4/H1-H4, который корректно
    # работает на iPhone, Mac, Android, Windows и роутерах. Формат vpn:// («для
    # приложения AmneziaVPN») сознательно НЕ отправляем — он не работает в нативном
    # AmneziaWG-клиенте и ломается на iOS/macOS (баг S3/S4 в приложении).
    MAX_LEN = 4000
    if len(config) <= MAX_LEN:
        await api.send_message(chat_id, f"<b>📄 Конфигурация (Оригинальный формат AmneziaWG):</b>\n<pre>{config}</pre>")
    else:
        chunks = [config[i:i + MAX_LEN] for i in range(0, len(config), MAX_LEN)]
        for i, chunk in enumerate(chunks, 1):
            await api.send_message(chat_id, f"<b>📄 Конфигурация (часть {i}/{len(chunks)}):</b>\n<pre>{chunk}</pre>")

    filename = f"{name.replace(' ', '_')}.conf"
    await api.send_document(
        chat_id, filename=filename, content=config.encode("utf-8"),
        caption=f"📁 {name} — Оригинальный формат AmneziaWG",
    )
    await api.send_message(
        chat_id,
        "📲 <b>Как подключить:</b>\n"
        "1. Установи приложение <b>AmneziaVPN</b> или <b>AmneziaWG</b>.\n"
        "2. Импортируй этот <b>.conf</b>-файл (или скопируй текст конфигурации выше).\n\n"
        "ℹ️ Это «Оригинальный формат AmneziaWG» — он корректно работает на iPhone, Mac, Android и Windows.",
    )


# ----------------------------------------------------------------------- #
#  Admin command: /newcode
# ----------------------------------------------------------------------- #
async def _handle_newcode(api: TelegramAPI, msg: dict, services: dict):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user or panel_user.get("role") != "admin":
        await api.send_message(chat_id, "❌ Команда доступна только администратору.")
        return
    # /newcode [count] [max_uses]
    parts = (msg.get("text", "") or "").split()
    count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
    max_uses = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 1
    codes = await asyncio.to_thread(services["create_invite_codes"], count, max_uses, "via bot /newcode", panel_user["username"])
    listing = "\n".join(f"<code>{c}</code>" for c in codes)
    await api.send_message(
        chat_id,
        f"✅ Создано кодов: {len(codes)} (использований на код: {max_uses})\n\n{listing}\n\n"
        "Передай код другу — он введёт его в боте при /start.",
    )


# ----------------------------------------------------------------------- #
#  Admin command: /broadcast — manual announcement to all users
# ----------------------------------------------------------------------- #
async def _handle_broadcast(api: TelegramAPI, msg: dict, services: dict):
    chat_id = msg["chat"]["id"]
    tg_id = str(msg["from"]["id"])
    panel_user = _find_user(services["load_data"], tg_id, services)
    if not panel_user or panel_user.get("role") != "admin":
        await api.send_message(chat_id, "❌ Команда доступна только администратору.")
        return
    parts = (msg.get("text", "") or "").split(maxsplit=1)
    body = parts[1].strip() if len(parts) > 1 else ""
    if not body:
        await api.send_message(
            chat_id,
            "✍️ Напиши текст после команды, например:\n"
            "<code>/broadcast Завтра плановые работы с 02:00 до 03:00 МСК</code>",
        )
        return
    res = await broadcast_custom(services, body, audience="all")
    await api.send_message(
        chat_id,
        f"📢 Рассылка отправлена.\n"
        f"Доставлено: <b>{res.get('sent', 0)}</b> из {res.get('total', 0)}"
        + (f"\nЗаблокировали бота: {res['blocked']}" if res.get("blocked") else "")
        + (f"\nОшибок: {res['failed']}" if res.get("failed") else ""),
    )


# ----------------------------------------------------------------------- #
#  Main polling loop
# ----------------------------------------------------------------------- #
# Command menu shown by Telegram's "Menu" button.
_PUBLIC_COMMANDS = [
    {"command": "start", "description": "Старт / регистрация по коду"},
    {"command": "menu", "description": "Меню: новое устройство и мои конфиги"},
    {"command": "help", "description": "Краткая инструкция по боту"},
]
_ADMIN_COMMANDS = _PUBLIC_COMMANDS + [
    {"command": "newcode", "description": "Создать код регистрации (админ)"},
    {"command": "broadcast", "description": "Рассылка всем пользователям (админ)"},
]


async def _setup_commands(api: TelegramAPI, services: dict):
    """Replace any stale command menu (e.g. left over from a previous use of
    this bot token) with our own. Public scope gets the basic list; each admin
    chat additionally sees /newcode."""
    # Clear all previously-configured commands across scopes we manage, then set ours.
    await api.call("deleteMyCommands")
    await api.call("setMyCommands", commands=_PUBLIC_COMMANDS)

    data = services["load_data"]()
    for u in data.get("users", []):
        if u.get("role") == "admin" and u.get("telegramId"):
            chat_id = str(u["telegramId"]).lstrip("@")
            try:
                await api.call(
                    "setMyCommands",
                    commands=_ADMIN_COMMANDS,
                    scope={"type": "chat", "chat_id": int(chat_id)},
                )
            except Exception as e:
                logger.warning(f"Telegram bot: failed to set admin commands for {chat_id}: {e}")
    logger.info("Telegram bot: command menu configured.")


async def _run_bot(token: str, services: dict):
    global _bot_api
    offset = 0
    logger.info("Telegram bot started (raw httpx polling).")

    async with httpx.AsyncClient() as client:
        api = TelegramAPI(token, client)
        _bot_api = api

        me = await api.call("getMe")
        if not me.get("ok"):
            logger.error(f"Telegram bot: invalid token or API error: {me}")
            _bot_api = None
            return
        logger.info(f"Telegram bot logged in as @{me['result']['username']}")

        try:
            await _setup_commands(api, services)
        except Exception as e:
            logger.warning(f"Telegram bot: failed to set command menu: {e}")

        try:
            while True:
                try:
                    updates = await api.get_updates(offset=offset, timeout=25)
                except asyncio.CancelledError:
                    logger.info("Telegram bot polling cancelled.")
                    return
                except Exception as e:
                    logger.warning(f"Telegram bot polling error: {e}")
                    await asyncio.sleep(5)
                    continue

                for update in updates:
                    offset = update["update_id"] + 1
                    try:
                        await _dispatch(api, update, services)
                    except asyncio.CancelledError:
                        return
                    except Exception as e:
                        logger.exception(f"Telegram bot: error handling update {update['update_id']}: {e}")
        finally:
            _bot_api = None


async def _dispatch(api: TelegramAPI, update: dict, services: dict):
    # --- Text messages ---
    if "message" in update:
        msg = update["message"]
        text = (msg.get("text", "") or "").strip()
        chat_id = msg["chat"]["id"]
        tg_id = str(msg["from"]["id"])
        first_name = msg["from"].get("first_name", "")

        if text.startswith("/start"):
            _pending.pop(tg_id, None)
            await _handle_start(api, msg, services)
            return
        if text.startswith("/newcode"):
            await _handle_newcode(api, msg, services)
            return
        if text.startswith("/broadcast") or text.startswith("/announce"):
            await _handle_broadcast(api, msg, services)
            return
        if text.startswith("/register"):
            parts = text.split(maxsplit=1)
            code = parts[1].strip() if len(parts) > 1 else ""
            if not code:
                await _show_welcome_for_new(api, chat_id, tg_id, first_name)
            else:
                await _try_register(api, chat_id, tg_id, first_name, code, services)
            return
        if text.startswith("/help"):
            await _show_help(api, chat_id, None, tg_id, services)
            return
        if text.startswith("/menu") or text.startswith("/connections"):
            await _show_menu(api, chat_id, None, tg_id, services)
            return

        # --- Stateful free text ---
        state = _pending.get(tg_id)
        if state and state.get("action") == "await_code":
            await _try_register(api, chat_id, tg_id, first_name, text, services)
            return
        if state and state.get("action") == "await_name":
            name = text[:48] or "Device"
            _pending.pop(tg_id, None)
            await _create_and_send(api, chat_id, tg_id, state["server_id"], state["protocol"], name, services)
            return

        # Unknown text — route by registration status
        if _find_user(services["load_data"], tg_id, services):
            await _show_menu(api, chat_id, None, tg_id, services)
        else:
            await _show_welcome_for_new(api, chat_id, tg_id, first_name)
        return

    # --- Inline button callbacks ---
    if "callback_query" in update:
        cq = update["callback_query"]
        callback_id = cq["id"]
        data_str = cq.get("data", "")
        chat_id = cq["message"]["chat"]["id"]
        message_id = cq["message"]["message_id"]
        tg_id = str(cq["from"]["id"])

        if data_str == "menu":
            await api.answer_callback(callback_id)
            await _show_menu(api, chat_id, message_id, tg_id, services)
        elif data_str == "new":
            await api.answer_callback(callback_id)
            await _show_servers(api, chat_id, message_id, services)
        elif data_str == "mine":
            await api.answer_callback(callback_id)
            await _show_my_connections(api, chat_id, message_id, tg_id, services)
        elif data_str == "status":
            await api.answer_callback(callback_id, "Проверяю серверы…")
            await _show_status(api, chat_id, message_id, tg_id, services)
        elif data_str == "help":
            await api.answer_callback(callback_id)
            await _show_help(api, chat_id, message_id, tg_id, services)
        elif data_str.startswith("srv:"):
            await api.answer_callback(callback_id)
            await _show_protocols(api, chat_id, message_id, int(data_str[4:]), services)
        elif data_str.startswith("proto:"):
            await api.answer_callback(callback_id)
            _, sid, proto = data_str.split(":", 2)
            await _ask_device_name(api, chat_id, message_id, tg_id, int(sid), proto, services)
        elif data_str.startswith("auto:"):
            await api.answer_callback(callback_id, "Создаю…")
            _, sid, proto = data_str.split(":", 2)
            _pending.pop(tg_id, None)
            # Inherently-unique auto name (random suffix); backend dedups as a safety net.
            import secrets
            auto_name = f"Device-{secrets.token_hex(2)}"
            await _create_and_send(api, chat_id, tg_id, int(sid), proto, auto_name, services)
        elif data_str.startswith("cfg:"):
            await _handle_get_existing_config(api, chat_id, callback_id, data_str[4:], tg_id, services)
        elif data_str.startswith("delok:"):
            await _do_delete(api, chat_id, callback_id, message_id, data_str[6:], tg_id, services)
        elif data_str.startswith("del:"):
            await _confirm_delete(api, chat_id, callback_id, message_id, data_str[4:], tg_id, services)
        else:
            await api.answer_callback(callback_id)
