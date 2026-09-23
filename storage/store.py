"""Store facade: SQLite primary, JSON snapshot for backup/export."""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlalchemy import delete, func, or_, select

from storage.db import SCHEMA_VERSION, get_session_factory, init_db
from storage.models import (
    ApiToken,
    AuditLog,
    InviteCode,
    SchemaMeta,
    Server,
    Setting,
    User,
    UserConnection,
)

logger = logging.getLogger(__name__)

MAX_AUDIT_ENTRIES = 5000

# Nested settings keys that are stored as separate Setting rows.
_SETTINGS_TOP_KEYS = (
    "appearance",
    "sync",
    "notifications",
    "monitor",
    "rkn_monitor",
    "backup",
    "audit",
    "telegram",
    "ssl",
    "captcha",
)

_USER_SCALAR = frozenset({
    "id", "username", "password_hash", "role", "enabled", "telegramId",
})
_SERVER_SCALAR = frozenset({"name", "host", "uuid", "id"})
_CONN_SCALAR = frozenset({
    "id", "user_id", "server_id", "protocol", "client_id", "name", "created_at",
})
_TOKEN_SCALAR = frozenset({"id", "token_hash", "user_id"})


class Store:
    """Panel persistence. Callers keep using the familiar dict shape via load_all/save_all."""

    def __init__(
        self,
        *,
        data_file: str,
        encrypt_fn: Callable[[Any], Any] | None = None,
        decrypt_fn: Callable[[Any], Any] | None = None,
        apply_secrets_fn: Callable[[dict, Callable], dict] | None = None,
        database_url: str | None = None,
    ):
        self.data_file = data_file
        self._encrypt_fn = encrypt_fn or (lambda x: x)
        self._decrypt_fn = decrypt_fn or (lambda x: x)
        self._apply_secrets = apply_secrets_fn or (lambda d, _fn: d)
        self._Session = get_session_factory(database_url)
        self._lock = threading.RLock()
        self._ready = False

    def init(self) -> None:
        with self._lock:
            init_db()
            with self._Session() as session:
                row = session.get(SchemaMeta, "version")
                if row is None:
                    session.add(SchemaMeta(key="version", value=str(SCHEMA_VERSION)))
                    session.commit()
                elif row.value != str(SCHEMA_VERSION):
                    row.value = str(SCHEMA_VERSION)
                    session.commit()
            self._ready = True
            self._bootstrap_from_json_if_needed()

    # ---- public: full document ------------------------------------------- #

    def load_all(self) -> dict:
        with self._lock:
            self._ensure_ready()
            data = self._read_from_db()
            # Fallback: if DB somehow empty but JSON exists, import then re-read.
            if not data.get("users") and not data.get("servers"):
                json_data = self._load_json_file()
                if json_data.get("users") or json_data.get("servers") or json_data.get("settings"):
                    self._import_document(json_data)
                    data = self._read_from_db()
            data = self._apply_defaults(data)
            return self._apply_secrets(data, self._decrypt_fn)

    def save_all(self, data: dict, *, replace_audit: bool = False) -> None:
        """Persist document to SQLite and write a JSON snapshot (no audit_log)."""
        with self._lock:
            self._ensure_ready()
            payload = self._apply_secrets(copy.deepcopy(data), self._encrypt_fn)
            self._write_to_db(payload, replace_audit=replace_audit)
            self._write_json_snapshot(payload)

    def export_snapshot(self) -> dict:
        """Plaintext (decrypted) full document including audit_log — for downloads."""
        data = self.load_all()
        data["audit_log"] = self._list_audit_entries(limit=MAX_AUDIT_ENTRIES)
        return data

    # ---- settings -------------------------------------------------------- #

    def get_settings(self) -> dict:
        return self.load_all().get("settings", {})

    def save_settings(self, settings: dict) -> None:
        data = self.load_all()
        data["settings"] = settings
        self.save_all(data)

    # ---- users ----------------------------------------------------------- #

    def list_users(self) -> list[dict]:
        return self.load_all().get("users", [])

    def get_user(self, user_id: str) -> dict | None:
        return next((u for u in self.list_users() if u.get("id") == user_id), None)

    # ---- servers --------------------------------------------------------- #

    def list_servers(self) -> list[dict]:
        return self.load_all().get("servers", [])

    # ---- connections ----------------------------------------------------- #

    def list_connections(self) -> list[dict]:
        return self.load_all().get("user_connections", [])

    # ---- audit ----------------------------------------------------------- #

    def append_audit(
        self,
        actor: str,
        action: str,
        target_type: str = "",
        target_id: str = "",
        details: dict | None = None,
        *,
        enabled: bool = True,
        retention_days: int = 30,
        force: bool = False,
    ) -> dict | None:
        if not force and not enabled:
            return None
        entry = {
            "id": str(uuid.uuid4()),
            "at": datetime.now().isoformat(),
            "actor": actor or "system",
            "action": action,
            "target_type": target_type or "",
            "target_id": str(target_id) if target_id else "",
            "details": details or {},
        }
        with self._lock:
            self._ensure_ready()
            with self._Session() as session:
                session.add(
                    AuditLog(
                        id=entry["id"],
                        ts=datetime.fromisoformat(entry["at"]),
                        actor=entry["actor"],
                        action=entry["action"],
                        target_type=entry["target_type"],
                        target_id=entry["target_id"],
                        detail=json.dumps(entry["details"], ensure_ascii=False),
                    )
                )
                session.commit()
            self.prune_audit(retention_days=retention_days)
        return entry

    def list_audit(
        self,
        *,
        search: str = "",
        action: str = "",
        page: int = 1,
        size: int = 50,
        enabled: bool = True,
        retention_days: int = 30,
    ) -> dict:
        with self._lock:
            self._ensure_ready()
            with self._Session() as session:
                q = select(AuditLog)
                if action:
                    q = q.where(AuditLog.action == action)
                if search:
                    like = f"%{search}%"
                    q = q.where(
                        or_(
                            AuditLog.actor.ilike(like),
                            AuditLog.action.ilike(like),
                            AuditLog.target_type.ilike(like),
                            AuditLog.target_id.ilike(like),
                            AuditLog.detail.ilike(like),
                        )
                    )
                q = q.order_by(AuditLog.ts.desc())
                rows = session.scalars(q).all()
                items = [self._audit_row_to_dict(r) for r in rows]

            total = len(items)
            page = max(1, page)
            size = max(1, min(size, 200))
            start = (page - 1) * size
            return {
                "entries": items[start : start + size],
                "total": total,
                "page": page,
                "size": size,
                "pages": (total + size - 1) // size if total else 0,
                "enabled": enabled,
                "retention_days": retention_days,
            }

    def prune_audit(self, *, retention_days: int = 30) -> int:
        with self._lock:
            self._ensure_ready()
            removed = 0
            with self._Session() as session:
                if retention_days and retention_days > 0:
                    cutoff = datetime.now() - timedelta(days=retention_days)
                    result = session.execute(
                        delete(AuditLog).where(AuditLog.ts < cutoff)
                    )
                    removed += result.rowcount or 0
                count = session.scalar(select(func.count()).select_from(AuditLog)) or 0
                if count > MAX_AUDIT_ENTRIES:
                    overflow = count - MAX_AUDIT_ENTRIES
                    old_ids = session.scalars(
                        select(AuditLog.id).order_by(AuditLog.ts.asc()).limit(overflow)
                    ).all()
                    if old_ids:
                        session.execute(delete(AuditLog).where(AuditLog.id.in_(old_ids)))
                        removed += len(old_ids)
                session.commit()
            return removed

    def clear_audit(self) -> int:
        with self._lock:
            self._ensure_ready()
            with self._Session() as session:
                n = session.scalar(select(func.count()).select_from(AuditLog)) or 0
                session.execute(delete(AuditLog))
                session.commit()
            return int(n)

    def audit_count(self) -> int:
        with self._lock:
            self._ensure_ready()
            with self._Session() as session:
                return int(session.scalar(select(func.count()).select_from(AuditLog)) or 0)

    # ---- internal -------------------------------------------------------- #

    def _ensure_ready(self) -> None:
        if not self._ready:
            self.init()

    def _bootstrap_from_json_if_needed(self) -> None:
        with self._Session() as session:
            has_users = (session.scalar(select(func.count()).select_from(User)) or 0) > 0
            has_servers = (session.scalar(select(func.count()).select_from(Server)) or 0) > 0
            has_settings = (session.scalar(select(func.count()).select_from(Setting)) or 0) > 0
            has_audit = (session.scalar(select(func.count()).select_from(AuditLog)) or 0) > 0
        if has_users or has_servers or has_settings:
            # Still import audit_log once if SQLite audit is empty.
            if not has_audit:
                json_data = self._load_json_file()
                audit = json_data.get("audit_log") or []
                if audit:
                    self._import_audit(audit)
                    self._strip_audit_from_json_file()
            return
        json_data = self._load_json_file()
        if not json_data:
            return
        logger.info("Importing panel state from %s into SQLite", self.data_file)
        self._import_document(json_data)
        self._strip_audit_from_json_file()

    def _load_json_file(self) -> dict:
        if not os.path.exists(self.data_file):
            return {}
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.error("Failed to read %s: %s", self.data_file, e)
            return {}

    def _strip_audit_from_json_file(self) -> None:
        """After audit import, stop growing the JSON key."""
        if not os.path.exists(self.data_file):
            return
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
            if not data.get("audit_log"):
                return
            data["audit_log"] = []
            self._atomic_write_json(data)
            logger.info("Cleared audit_log from JSON after SQLite import")
        except Exception as e:
            logger.warning("Could not strip audit_log from JSON: %s", e)

    def _atomic_write_json(self, data: dict) -> None:
        import tempfile

        target_dir = os.path.dirname(self.data_file) or "."
        os.makedirs(target_dir, exist_ok=True)
        serialized = json.dumps(data, indent=2, ensure_ascii=False)
        fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".data.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.data_file)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _write_json_snapshot(self, encrypted_data: dict) -> None:
        """Write JSON mirror without audit_log (lives only in SQLite)."""
        snap = {
            "servers": encrypted_data.get("servers", []),
            "users": encrypted_data.get("users", []),
            "user_connections": encrypted_data.get("user_connections", []),
            "api_tokens": encrypted_data.get("api_tokens", []),
            "invite_codes": encrypted_data.get("invite_codes", []),
            "settings": encrypted_data.get("settings", {}),
            "audit_log": [],
        }
        # Preserve any unknown top-level keys from prior JSON (forward-compat).
        existing = self._load_json_file()
        for k, v in existing.items():
            if k not in snap:
                snap[k] = v
        self._atomic_write_json(snap)

    def _import_document(self, data: dict) -> None:
        # data may have encrypted secrets — store as-is (ciphertext in DB columns).
        with self._Session() as session:
            session.execute(delete(User))
            session.execute(delete(InviteCode))
            session.execute(delete(ApiToken))
            session.execute(delete(Server))
            session.execute(delete(UserConnection))
            session.execute(delete(Setting))
            session.commit()

        self._write_to_db(data, replace_audit=False)
        audit = data.get("audit_log") or []
        if audit:
            self._import_audit(audit)

    def _import_audit(self, entries: list) -> None:
        with self._Session() as session:
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                eid = str(entry.get("id") or uuid.uuid4())
                if session.get(AuditLog, eid):
                    continue
                raw_ts = entry.get("at")
                try:
                    ts = datetime.fromisoformat(raw_ts) if raw_ts else datetime.now()
                except (TypeError, ValueError):
                    ts = datetime.now()
                session.add(
                    AuditLog(
                        id=eid,
                        ts=ts,
                        actor=str(entry.get("actor") or "system"),
                        action=str(entry.get("action") or ""),
                        target_type=str(entry.get("target_type") or ""),
                        target_id=str(entry.get("target_id") or ""),
                        detail=json.dumps(entry.get("details") or {}, ensure_ascii=False),
                    )
                )
            session.commit()
        logger.info("Imported %s audit_log entries into SQLite", len(entries))

    def _write_to_db(self, data: dict, *, replace_audit: bool = False) -> None:
        with self._Session() as session:
            # users
            session.execute(delete(User))
            for u in data.get("users") or []:
                if not isinstance(u, dict) or not u.get("id"):
                    continue
                payload = {k: v for k, v in u.items() if k not in _USER_SCALAR}
                tg = u.get("telegramId")
                session.add(
                    User(
                        id=str(u["id"]),
                        username=str(u.get("username") or ""),
                        telegram_id=str(tg).lstrip("@") if tg else None,
                        password_hash=str(u.get("password_hash") or ""),
                        role=str(u.get("role") or "user"),
                        enabled=bool(u.get("enabled", True)),
                        payload=json.dumps(payload, ensure_ascii=False),
                    )
                )

            # invite codes
            session.execute(delete(InviteCode))
            for c in data.get("invite_codes") or []:
                if not isinstance(c, dict) or not c.get("code"):
                    continue
                session.add(
                    InviteCode(
                        code=str(c["code"]),
                        payload=json.dumps(c, ensure_ascii=False),
                    )
                )

            # api tokens
            session.execute(delete(ApiToken))
            for t in data.get("api_tokens") or []:
                if not isinstance(t, dict) or not t.get("id"):
                    continue
                payload = {k: v for k, v in t.items() if k not in _TOKEN_SCALAR}
                session.add(
                    ApiToken(
                        id=str(t["id"]),
                        token_hash=str(t.get("token_hash") or ""),
                        user_id=str(t.get("user_id") or ""),
                        payload=json.dumps(payload, ensure_ascii=False),
                    )
                )

            # servers — preserve array order as legacy_index
            session.execute(delete(Server))
            for idx, srv in enumerate(data.get("servers") or []):
                if not isinstance(srv, dict):
                    continue
                sid = str(srv.get("uuid") or srv.get("id") or uuid.uuid4())
                # Avoid colliding with non-uuid legacy fields; always prefer uuid key.
                if "uuid" in srv:
                    sid = str(srv["uuid"])
                elif not _looks_like_uuid(sid):
                    sid = str(uuid.uuid4())
                payload = dict(srv)
                payload["uuid"] = sid
                payload.pop("id", None)
                session.add(
                    Server(
                        id=sid,
                        legacy_index=idx,
                        name=str(srv.get("name") or ""),
                        host=str(srv.get("host") or ""),
                        payload=json.dumps(payload, ensure_ascii=False),
                    )
                )

            # connections
            session.execute(delete(UserConnection))
            for c in data.get("user_connections") or []:
                if not isinstance(c, dict) or not c.get("id"):
                    continue
                payload = {k: v for k, v in c.items() if k not in _CONN_SCALAR}
                session.add(
                    UserConnection(
                        id=str(c["id"]),
                        user_id=str(c.get("user_id") or ""),
                        server_id=int(c.get("server_id") or 0),
                        protocol=str(c.get("protocol") or ""),
                        client_id=str(c.get("client_id") or ""),
                        name=str(c.get("name") or ""),
                        created_at=str(c.get("created_at") or ""),
                        payload=json.dumps(payload, ensure_ascii=False),
                    )
                )

            # settings — one row per top-level key + leftovers under _extra
            session.execute(delete(Setting))
            settings = data.get("settings") or {}
            if isinstance(settings, dict):
                known = set()
                for key in _SETTINGS_TOP_KEYS:
                    if key in settings:
                        session.add(
                            Setting(
                                key=key,
                                value_json=json.dumps(settings[key], ensure_ascii=False),
                            )
                        )
                        known.add(key)
                extra = {k: v for k, v in settings.items() if k not in known}
                if extra:
                    session.add(
                        Setting(
                            key="_extra",
                            value_json=json.dumps(extra, ensure_ascii=False),
                        )
                    )

            if replace_audit:
                session.execute(delete(AuditLog))
                for entry in data.get("audit_log") or []:
                    if not isinstance(entry, dict):
                        continue
                    eid = str(entry.get("id") or uuid.uuid4())
                    raw_ts = entry.get("at")
                    try:
                        ts = datetime.fromisoformat(raw_ts) if raw_ts else datetime.now()
                    except (TypeError, ValueError):
                        ts = datetime.now()
                    session.add(
                        AuditLog(
                            id=eid,
                            ts=ts,
                            actor=str(entry.get("actor") or "system"),
                            action=str(entry.get("action") or ""),
                            target_type=str(entry.get("target_type") or ""),
                            target_id=str(entry.get("target_id") or ""),
                            detail=json.dumps(entry.get("details") or {}, ensure_ascii=False),
                        )
                    )

            session.commit()

    def _read_from_db(self) -> dict:
        with self._Session() as session:
            users = []
            for row in session.scalars(select(User)).all():
                try:
                    payload = json.loads(row.payload or "{}")
                except json.JSONDecodeError:
                    payload = {}
                u = dict(payload)
                u.update({
                    "id": row.id,
                    "username": row.username,
                    "password_hash": row.password_hash,
                    "role": row.role,
                    "enabled": row.enabled,
                    "telegramId": row.telegram_id,
                })
                users.append(u)

            invites = []
            for row in session.scalars(select(InviteCode)).all():
                try:
                    invites.append(json.loads(row.payload or "{}"))
                except json.JSONDecodeError:
                    invites.append({"code": row.code})

            tokens = []
            for row in session.scalars(select(ApiToken)).all():
                try:
                    payload = json.loads(row.payload or "{}")
                except json.JSONDecodeError:
                    payload = {}
                t = dict(payload)
                t.update({
                    "id": row.id,
                    "token_hash": row.token_hash,
                    "user_id": row.user_id,
                })
                tokens.append(t)

            servers = []
            for row in session.scalars(
                select(Server).order_by(Server.legacy_index.asc())
            ).all():
                try:
                    payload = json.loads(row.payload or "{}")
                except json.JSONDecodeError:
                    payload = {}
                srv = dict(payload)
                srv["uuid"] = row.id
                if not srv.get("name"):
                    srv["name"] = row.name
                if not srv.get("host"):
                    srv["host"] = row.host
                servers.append(srv)

            conns = []
            for row in session.scalars(select(UserConnection)).all():
                try:
                    payload = json.loads(row.payload or "{}")
                except json.JSONDecodeError:
                    payload = {}
                c = dict(payload)
                c.update({
                    "id": row.id,
                    "user_id": row.user_id,
                    "server_id": row.server_id,
                    "protocol": row.protocol,
                    "client_id": row.client_id,
                    "name": row.name,
                    "created_at": row.created_at,
                })
                conns.append(c)

            settings: dict[str, Any] = {}
            for row in session.scalars(select(Setting)).all():
                try:
                    value = json.loads(row.value_json or "{}")
                except json.JSONDecodeError:
                    value = {}
                if row.key == "_extra" and isinstance(value, dict):
                    settings.update(value)
                else:
                    settings[row.key] = value

        return {
            "users": users,
            "invite_codes": invites,
            "api_tokens": tokens,
            "servers": servers,
            "user_connections": conns,
            "settings": settings,
            "audit_log": [],  # live audit is SQLite-only
        }

    def _list_audit_entries(self, *, limit: int = MAX_AUDIT_ENTRIES) -> list[dict]:
        with self._Session() as session:
            rows = session.scalars(
                select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
            ).all()
            # export oldest→newest
            return [self._audit_row_to_dict(r) for r in reversed(list(rows))]

    @staticmethod
    def _audit_row_to_dict(row: AuditLog) -> dict:
        try:
            details = json.loads(row.detail or "{}")
        except json.JSONDecodeError:
            details = {}
        return {
            "id": row.id,
            "at": row.ts.isoformat() if row.ts else "",
            "actor": row.actor,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "details": details,
        }

    @staticmethod
    def _apply_defaults(data: dict) -> dict:
        data.setdefault("servers", [])
        data.setdefault("users", [])
        data.setdefault("user_connections", [])
        data.setdefault("api_tokens", [])
        data.setdefault("invite_codes", [])
        data.setdefault("audit_log", [])
        data.setdefault("settings", {})
        return data


def _looks_like_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


_store: Store | None = None
_store_lock = threading.Lock()


def get_store() -> Store:
    if _store is None:
        raise RuntimeError("Store not initialised — call configure_store() first")
    return _store


def configure_store(
    *,
    data_file: str,
    encrypt_fn: Callable | None = None,
    decrypt_fn: Callable | None = None,
    apply_secrets_fn: Callable | None = None,
    database_url: str | None = None,
) -> Store:
    global _store
    with _store_lock:
        _store = Store(
            data_file=data_file,
            encrypt_fn=encrypt_fn,
            decrypt_fn=decrypt_fn,
            apply_secrets_fn=apply_secrets_fn,
            database_url=database_url,
        )
        _store.init()
        return _store
