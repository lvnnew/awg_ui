"""Append-only admin audit log stored in data.json."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

# Hard safety cap if retention is misconfigured.
MAX_ENTRIES = 5000


def default_audit_settings() -> dict:
    return {
        'enabled': True,
        'retention_days': 30,
    }


def get_audit_settings(data: dict) -> dict:
    cfg = data.get('settings', {}).get('audit') or {}
    return {**default_audit_settings(), **cfg}


def audit_enabled(data: dict) -> bool:
    return bool(get_audit_settings(data).get('enabled', True))


def prune_audit_log(data: dict) -> int:
    """Drop entries older than retention_days. Returns number removed."""
    days = int(get_audit_settings(data).get('retention_days') or 0)
    log = data.get('audit_log') or []
    if not log:
        return 0
    if days <= 0:
        # No time-based retention; still enforce hard cap.
        if len(log) > MAX_ENTRIES:
            removed = len(log) - MAX_ENTRIES
            data['audit_log'] = log[-MAX_ENTRIES:]
            return removed
        return 0
    cutoff = datetime.now() - timedelta(days=days)
    kept = []
    removed = 0
    for entry in log:
        raw = entry.get('at')
        try:
            if datetime.fromisoformat(raw) >= cutoff:
                kept.append(entry)
            else:
                removed += 1
        except (TypeError, ValueError):
            kept.append(entry)
    if len(kept) > MAX_ENTRIES:
        removed += len(kept) - MAX_ENTRIES
        kept = kept[-MAX_ENTRIES:]
    data['audit_log'] = kept
    return removed


def clear_audit_log(data: dict) -> int:
    n = len(data.get('audit_log') or [])
    data['audit_log'] = []
    return n


def append_audit(
    data: dict,
    actor: str,
    action: str,
    target_type: str = '',
    target_id: str = '',
    details: dict | None = None,
    *,
    force: bool = False,
) -> dict | None:
    """Append an audit entry to data (caller saves). Returns the new entry."""
    if not force and not audit_enabled(data):
        return None
    entry = {
        'id': str(uuid.uuid4()),
        'at': datetime.now().isoformat(),
        'actor': actor or 'system',
        'action': action,
        'target_type': target_type or '',
        'target_id': str(target_id) if target_id else '',
        'details': details or {},
    }
    log = data.setdefault('audit_log', [])
    log.append(entry)
    prune_audit_log(data)
    return entry


def list_audit(
    data: dict,
    *,
    search: str = '',
    action: str = '',
    page: int = 1,
    size: int = 50,
) -> dict:
    items = list(data.get('audit_log') or [])
    items.reverse()  # newest first

    search = (search or '').lower().strip()
    action = (action or '').strip()

    if action:
        items = [e for e in items if e.get('action') == action]
    if search:
        def _match(e: dict) -> bool:
            hay = ' '.join([
                str(e.get('actor', '')),
                str(e.get('action', '')),
                str(e.get('target_type', '')),
                str(e.get('target_id', '')),
            ]).lower()
            if search in hay:
                return True
            det = e.get('details') or {}
            return search in str(det).lower()
        items = [e for e in items if _match(e)]

    total = len(items)
    page = max(1, page)
    size = max(1, min(size, 200))
    start = (page - 1) * size
    page_items = items[start:start + size]
    return {
        'entries': page_items,
        'total': total,
        'page': page,
        'size': size,
        'pages': (total + size - 1) // size if total else 0,
        'enabled': audit_enabled(data),
        'retention_days': get_audit_settings(data).get('retention_days', 30),
    }


def user_last_activity_at(user: dict) -> datetime | None:
    """Latest panel login or bot activity."""
    stamps = []
    for key in ('last_login_at', 'last_bot_at'):
        raw = user.get(key)
        if raw:
            try:
                stamps.append(datetime.fromisoformat(raw))
            except ValueError:
                pass
    return max(stamps) if stamps else None


def filter_users(
    users: list,
    conns: list,
    *,
    search: str = '',
    role: str = '',
    enabled: str = '',
    inactive_days: int = 0,
    has_connections: str = '',
) -> list:
    search = (search or '').lower().strip()
    role = (role or '').strip().lower()
    enabled = (enabled or '').strip().lower()
    has_connections = (has_connections or '').strip().lower()
    cutoff = None
    if inactive_days and inactive_days > 0:
        cutoff = datetime.now() - timedelta(days=inactive_days)

    conn_counts: dict[str, int] = {}
    for c in conns:
        uid = c.get('user_id')
        if uid:
            conn_counts[uid] = conn_counts.get(uid, 0) + 1

    out = []
    for u in users:
        if search:
            match = (
                search in u.get('username', '').lower()
                or (u.get('email') and search in u['email'].lower())
                or (u.get('telegramId') and search in str(u['telegramId']).lower())
                or (u.get('invite_code') and search in str(u['invite_code']).lower())
            )
            if not match:
                continue
        if role and role != 'all' and u.get('role') != role:
            continue
        if enabled == 'true' and not u.get('enabled', True):
            continue
        if enabled == 'false' and u.get('enabled', True):
            continue
        cc = conn_counts.get(u.get('id'), 0)
        if has_connections == 'yes' and cc == 0:
            continue
        if has_connections == 'no' and cc > 0:
            continue
        if cutoff is not None:
            last = user_last_activity_at(u)
            if last is not None:
                if last >= cutoff:
                    continue
            else:
                created_raw = u.get('created_at')
                if created_raw:
                    try:
                        if datetime.fromisoformat(created_raw) >= cutoff:
                            continue
                    except ValueError:
                        pass
        out.append(u)
    return out


def serialize_user_row(u: dict, conns: list) -> dict:
    return {
        'id': u['id'],
        'username': u['username'],
        'role': u['role'],
        'enabled': u.get('enabled', True),
        'created_at': u.get('created_at', ''),
        'telegramId': u.get('telegramId'),
        'email': u.get('email'),
        'description': u.get('description'),
        'connections_count': sum(1 for c in conns if c['user_id'] == u['id']),
        'traffic_used': u.get('traffic_used', 0),
        'traffic_total': u.get('traffic_total', 0),
        'traffic_limit': u.get('traffic_limit', 0),
        'traffic_reset_strategy': u.get('traffic_reset_strategy', 'never'),
        'expiration_date': u.get('expiration_date'),
        'share_enabled': u.get('share_enabled', False),
        'share_token': u.get('share_token'),
        'has_share_password': bool(u.get('share_password_hash')),
        'source': 'Remnawave' if u.get('remnawave_uuid') else 'Local',
        'invite_code': u.get('invite_code'),
        'last_login_at': u.get('last_login_at'),
        'last_bot_at': u.get('last_bot_at'),
        'last_reset_at': u.get('last_reset_at'),
    }
