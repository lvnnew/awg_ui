"""RKN (Roskomnadzor) blocklist monitor helpers.

Downloads/caches the public zapret-info dump and matches *only* fleet IPs
against it (streamed — never loads the full registry into RAM). Also parses
AmneziaWG `awg show` for stale-handshake DPI symptoms.
"""

from __future__ import annotations

import gzip
import ipaddress
import logging
import os
import re
import shutil
import time
from typing import Optional
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

DEFAULT_DUMP_URL = (
    "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz"
)

AWG_CONTAINERS = {
    "awg": "amnezia-awg",
    "awg3": "amnezia-awg3",
    "awg2": "amnezia-awg2",
    "awg_legacy": "amnezia-awg-legacy",
}

_HANDSHAKE_UNIT = {
    "second": 1,
    "seconds": 1,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
    "week": 604800,
    "weeks": 604800,
}

_TRANSFER_UNIT = {
    "B": 1,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
}

_LEVEL_RANK = {"ok": 0, "at_risk": 1, "blocked": 2}


def default_rkn_monitor_settings() -> dict:
    return {
        "enabled": True,
        "interval_seconds": 900,
        "dump_refresh_seconds": 14400,
        "fail_threshold": 2,
        "check_registry": True,
        "check_handshake": True,
        "handshake_stale_hours": 6,
        "notify_clear": True,
        "dump_url": DEFAULT_DUMP_URL,
    }


class RknDumpIndex:
    """Lightweight scan result for a small set of watched IPv4 addresses.

    Does NOT hold the full RKN dump in memory (that OOMs a 512Mi panel).
    """

    def __init__(self):
        self.levels: dict[str, str] = {}  # ip -> ok|at_risk|blocked
        self.loaded_at: float = 0.0
        self.source: str = ""
        self.entry_count: int = 0  # tokens inspected
        self.watched: int = 0

    @property
    def ready(self) -> bool:
        return bool(self.source) and self.loaded_at > 0

    # Back-compat for status API fields that used to report set sizes
    @property
    def exact(self):
        return {ip for ip, lv in self.levels.items() if lv == "blocked"}

    @property
    def networks(self):
        return []

    def match_ip(self, ip_str: str) -> str:
        ip = (ip_str or "").strip()
        return self.levels.get(ip, "ok")


_index: Optional[RknDumpIndex] = None
_index_lock = __import__("threading").RLock()
_dump_path: Optional[str] = None
_dump_fetched_at: float = 0.0


def cache_dir_for_data_file(data_file: str) -> str:
    base = os.path.dirname(os.path.abspath(data_file)) or "."
    return os.path.join(base, "rkn_cache")


def _dump_paths(cache_dir: str) -> tuple[str, str]:
    return (
        os.path.join(cache_dir, "dump.csv.gz"),
        os.path.join(cache_dir, "dump.csv"),
    )


def find_cached_dump(cache_dir: str) -> Optional[str]:
    gz, plain = _dump_paths(cache_dir)
    if os.path.isfile(gz) and os.path.getsize(gz) > 0:
        return gz
    if os.path.isfile(plain) and os.path.getsize(plain) > 0:
        return plain
    return None


def download_dump(url: str, cache_dir: str, timeout: int = 180) -> str:
    """Stream dump to disk (no full-body RAM buffer)."""
    os.makedirs(cache_dir, exist_ok=True)
    req = Request(url, headers={"User-Agent": "awg-fork-rkn-monitor/1.1"})
    dest = os.path.join(
        cache_dir,
        "dump.csv.gz" if url.endswith(".gz") else "dump.csv",
    )
    tmp = dest + ".tmp"
    with urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
        # Prefer Content-Encoding-aware body as-is (github serves .gz raw)
        shutil.copyfileobj(resp, out, length=1024 * 1024)
    os.replace(tmp, dest)
    meta = os.path.join(cache_dir, "meta.txt")
    with open(meta, "w", encoding="utf-8") as f:
        f.write(f"url={url}\nfetched_at={time.time()}\nsize={os.path.getsize(dest)}\n")
    logger.info("RKN dump saved %s (%s bytes)", dest, os.path.getsize(dest))
    return dest


def ensure_dump_file(
    cache_dir: str,
    url: str = DEFAULT_DUMP_URL,
    refresh_seconds: int = 14400,
    force: bool = False,
) -> str:
    """Return path to a fresh-enough dump file on disk."""
    global _dump_path, _dump_fetched_at
    with _index_lock:
        now = time.time()
        cached = find_cached_dump(cache_dir)
        if (
            not force
            and cached
            and (now - os.path.getmtime(cached)) < refresh_seconds
        ):
            _dump_path = cached
            _dump_fetched_at = os.path.getmtime(cached)
            return cached
        try:
            path = download_dump(url, cache_dir)
            _dump_path = path
            _dump_fetched_at = time.time()
            return path
        except Exception as e:
            logger.error("RKN dump download failed: %s", e)
            if cached:
                _dump_path = cached
                _dump_fetched_at = os.path.getmtime(cached)
                return cached
            raise


def _open_dump_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "rt", encoding="utf-8", errors="ignore")


def _raise_level(cur: str, new: str) -> str:
    return new if _LEVEL_RANK.get(new, 0) > _LEVEL_RANK.get(cur, 0) else cur


def match_ips_in_dump(dump_path: str, ip_list: list[str]) -> RknDumpIndex:
    """Stream-scan dump; only track the given IPv4 addresses (O(fleet) memory)."""
    idx = RknDumpIndex()
    idx.source = dump_path
    # watch: ip_str -> {n, s24, level}
    watches: dict[str, dict] = {}
    by_int: dict[int, str] = {}
    by_s24: dict[int, list[str]] = {}

    for raw in ip_list:
        ip_s = (raw or "").strip()
        if not ip_s or ip_s in watches:
            continue
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        if not isinstance(ip, ipaddress.IPv4Address):
            continue
        n = int(ip)
        watches[ip_s] = {"n": n, "s24": n >> 8, "level": "ok"}
        by_int[n] = ip_s
        by_s24.setdefault(n >> 8, []).append(ip_s)

    idx.watched = len(watches)
    if not watches:
        idx.loaded_at = time.time()
        return idx

    tokens = 0
    try:
        with _open_dump_text(dump_path) as fh:
            for line in fh:
                if not line or line.startswith("Updated:") or line.lower().startswith("ip;"):
                    continue
                first = line.split(";", 1)[0]
                for part in first.split("|"):
                    token = part.strip()
                    if not token:
                        continue
                    tokens += 1
                    try:
                        if "/" in token:
                            net = ipaddress.ip_network(token, strict=False)
                            if not isinstance(net, ipaddress.IPv4Network):
                                continue
                            # Exact /32
                            if net.prefixlen == 32:
                                hit = by_int.get(int(net.network_address))
                                if hit:
                                    watches[hit]["level"] = "blocked"
                                # neighbour pressure for same /24
                                s24 = int(net.network_address) >> 8
                                for wip in by_s24.get(s24, []):
                                    if watches[wip]["level"] != "blocked":
                                        watches[wip]["level"] = _raise_level(
                                            watches[wip]["level"], "at_risk"
                                        )
                                continue
                            # CIDR contains a watched IP → blocked
                            for wip, w in watches.items():
                                if w["level"] == "blocked":
                                    continue
                                if ipaddress.IPv4Address(w["n"]) in net:
                                    w["level"] = "blocked"
                                elif (int(net.network_address) >> 8) <= w["s24"] <= (
                                    int(net.broadcast_address) >> 8
                                ):
                                    # overlapping /24 space → neighbour risk if not blocked
                                    w["level"] = _raise_level(w["level"], "at_risk")
                        else:
                            ip = ipaddress.ip_address(token)
                            if not isinstance(ip, ipaddress.IPv4Address):
                                continue
                            n = int(ip)
                            hit = by_int.get(n)
                            if hit:
                                watches[hit]["level"] = "blocked"
                                continue
                            for wip in by_s24.get(n >> 8, []):
                                if watches[wip]["level"] != "blocked":
                                    watches[wip]["level"] = _raise_level(
                                        watches[wip]["level"], "at_risk"
                                    )
                    except ValueError:
                        continue
    except Exception as e:
        logger.error("RKN dump scan failed: %s", e)
        raise

    idx.entry_count = tokens
    idx.levels = {ip: w["level"] for ip, w in watches.items()}
    idx.loaded_at = time.time()
    try:
        idx.dump_mtime = os.path.getmtime(dump_path)
    except OSError:
        idx.dump_mtime = idx.loaded_at
    logger.info(
        "RKN scan done path=%s watched=%s tokens≈%s blocked=%s at_risk=%s",
        dump_path,
        idx.watched,
        tokens,
        sum(1 for lv in idx.levels.values() if lv == "blocked"),
        sum(1 for lv in idx.levels.values() if lv == "at_risk"),
    )
    return idx


def ensure_dump_index(
    cache_dir: str,
    url: str = DEFAULT_DUMP_URL,
    refresh_seconds: int = 14400,
    force: bool = False,
    watch_ips: Optional[list[str]] = None,
) -> RknDumpIndex:
    """Ensure dump file exists, then (re)scan for watch_ips."""
    global _index
    path = ensure_dump_file(cache_dir, url=url, refresh_seconds=refresh_seconds, force=force)
    ips = list(watch_ips or [])
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0.0
    with _index_lock:
        if (
            not force
            and _index is not None
            and _index.ready
            and _index.source == path
            and set(_index.levels.keys()) == set(ips)
            and getattr(_index, "dump_mtime", None) == mtime
        ):
            return _index
        _index = match_ips_in_dump(path, ips)
        return _index


def get_dump_index() -> Optional[RknDumpIndex]:
    return _index


def parse_handshake_age_seconds(text: str) -> Optional[int]:
    """Parse WireGuard/Amnezia 'latest handshake: … ago' into seconds, or None."""
    if not text:
        return None
    t = text.strip().lower()
    if t in ("never", "(none)", "none"):
        return None
    if t.endswith(" ago"):
        t = t[: -len(" ago")].strip()
    total = 0
    found = False
    for num, unit in re.findall(r"(\d+)\s+([a-z]+)", t):
        mult = _HANDSHAKE_UNIT.get(unit)
        if mult is None:
            continue
        total += int(num) * mult
        found = True
    return total if found else None


def parse_transfer_bytes(text: str) -> int:
    """Sum received+sent from 'transfer: 1.2 KiB received, 3.4 MiB sent'."""
    if not text:
        return 0
    total = 0
    for num, unit in re.findall(
        r"([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\s+(?:received|sent)", text, re.I
    ):
        total += int(float(num) * _TRANSFER_UNIT.get(unit, 1))
    return total


def parse_awg_show(output: str) -> list[dict]:
    """Extract peer handshake/transfer facts from `awg show all` / `wg show all`."""
    peers = []
    cur = None
    for line in (output or "").splitlines():
        raw = line.rstrip()
        if raw.startswith("peer:"):
            if cur:
                peers.append(cur)
            cur = {
                "public_key": raw.split(":", 1)[1].strip(),
                "handshake_age": None,
                "transfer": 0,
            }
            continue
        if cur is None:
            continue
        s = raw.strip()
        if s.startswith("latest handshake:"):
            cur["handshake_age"] = parse_handshake_age_seconds(s.split(":", 1)[1])
        elif s.startswith("transfer:"):
            cur["transfer"] = parse_transfer_bytes(s.split(":", 1)[1])
    if cur:
        peers.append(cur)
    return peers


def parse_size_to_bytes(value) -> int:
    """Parse int bytes or human sizes like '283.37 GiB' / '12.5 MiB'."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().replace(",", ".")
    if not s:
        return 0
    try:
        return int(float(s))
    except ValueError:
        pass
    m = re.match(r"^([\d.]+)\s*(B|KiB|MiB|GiB|TiB|KB|MB|GB|TB)?$", s, re.I)
    if not m:
        return 0
    num = float(m.group(1))
    unit = (m.group(2) or "B").upper()
    mult = {
        "B": 1,
        "KIB": 1024,
        "KB": 1000,
        "MIB": 1024**2,
        "MB": 1000**2,
        "GIB": 1024**3,
        "GB": 1000**3,
        "TIB": 1024**4,
        "TB": 1000**4,
    }.get(unit, 1)
    return int(num * mult)


def format_age(seconds: Optional[int]) -> str:
    if seconds is None:
        return "никогда / сброс счётчиков"
    s = int(seconds)
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}д")
    if hours or days:
        parts.append(f"{hours}ч")
    if not days:
        parts.append(f"{minutes}м")
    return " ".join(parts)


def evaluate_handshake_symptom(
    peers: list[dict],
    stale_hours: float = 6.0,
    name_by_key: Optional[dict] = None,
    lifetime_bytes_by_key: Optional[dict] = None,
) -> Optional[dict]:
    """If peers look unreachable, return structured symptom details.

    History comes from live `wg/awg show` transfer **or** lifetime counters in
    clientsTable (survive container remaps that zero WireGuard stats — PL1 case).
    """
    stale_sec = max(1.0, float(stale_hours)) * 3600
    names = name_by_key or {}
    lifetime = lifetime_bytes_by_key or {}

    with_history = []
    for p in peers:
        key = p.get("public_key") or ""
        live = int(p.get("transfer") or 0)
        hist = int(lifetime.get(key) or 0)
        if live > 0 or hist > 0:
            with_history.append({**p, "lifetime_bytes": hist, "live_transfer": live})
    if not with_history:
        return None

    # Any recent handshake among historically-used peers → healthy
    for p in with_history:
        age = p.get("handshake_age")
        if age is not None and age < stale_sec:
            return None

    stale_peers = []
    for p in with_history:
        key = p.get("public_key") or ""
        age = p.get("handshake_age")
        stale_peers.append({
            "name": names.get(key) or (key[:8] + "…" if key else "?"),
            "public_key": key,
            "age_seconds": age,
            "age_label": format_age(age),
            "transfer": p.get("live_transfer") or 0,
            "lifetime_bytes": p.get("lifetime_bytes") or 0,
        })

    ages = [p["age_seconds"] for p in stale_peers if p["age_seconds"] is not None]
    oldest = max(ages) if ages else None
    # If all handshakes missing after remap, still treat as fully silent.
    if oldest is None:
        code = "peers_silent_after_reset"
    else:
        code = "no_handshake"

    return {
        "code": code,
        "stale_count": len(stale_peers),
        "oldest_seconds": oldest,
        "threshold_hours": float(stale_hours),
        "peers": stale_peers,
    }


def humanize_handshake_symptom(proto: str, sym: dict) -> str:
    """Russian one-liner for UI/Telegram."""
    names = [p.get("name") for p in (sym.get("peers") or []) if p.get("name")]
    names_s = ", ".join(names[:5])
    if len(names) > 5:
        names_s += f" и ещё {len(names) - 5}"
    thr = sym.get("threshold_hours") or 6
    n = sym.get("stale_count", 0)
    if sym.get("code") == "peers_silent_after_reset":
        return (
            f"{proto}: {n} клиент(ов) раньше имели трафик, но сейчас нет ни одного "
            f"handshake (счётчики WG обнулены — типично после рестарта/ремапа; "
            f"с РФ, скорее всего, UDP не доходит)"
            + (f" — {names_s}" if names_s else "")
        )
    age = format_age(sym.get("oldest_seconds"))
    return (
        f"{proto}: нет живого handshake ≥{thr}ч у {n} "
        f"клиент(ов) с трафиком (давность до {age})"
        + (f" — {names_s}" if names_s else "")
    )


def load_awg_clients_meta(ssh, container: str) -> dict:
    """Return {public_key: {name, lifetime_bytes}} from clientsTable."""
    import json as _json

    cmd = f"docker exec {container} cat /opt/amnezia/awg/clientsTable 2>/dev/null"
    try:
        if hasattr(ssh, "run_sudo_command"):
            out, _err, code = ssh.run_sudo_command(cmd, timeout=30)
        else:
            out, _err, code = ssh.run_command(cmd, timeout=30)
    except Exception:
        return {}
    if code != 0 or not out:
        return {}
    try:
        rows = _json.loads(out)
    except Exception:
        return {}
    meta = {}
    if isinstance(rows, list):
        for row in rows:
            cid = row.get("clientId") or row.get("public_key")
            if not cid:
                continue
            ud = row.get("userData") or {}
            name = ud.get("clientName") or row.get("clientName") or ""
            rx = parse_size_to_bytes(
                ud.get("dataReceivedBytes", ud.get("dataReceived"))
            )
            tx = parse_size_to_bytes(
                ud.get("dataSentBytes", ud.get("dataSent"))
            )
            meta[cid] = {"name": name, "lifetime_bytes": rx + tx}
    return meta


def load_awg_client_names(ssh, container: str) -> dict:
    """Map peer public key → clientName from clientsTable JSON."""
    return {
        k: (v.get("name") or "")
        for k, v in load_awg_clients_meta(ssh, container).items()
        if v.get("name")
    }


def resolve_host_ipv4(host: str) -> Optional[str]:
    """Return IPv4 for host (literal or DNS)."""
    host = (host or "").strip()
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            return str(ip)
        return None
    except ValueError:
        pass
    import socket

    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except OSError:
        return None
    return None


def check_server_registry(index: RknDumpIndex, host: str) -> dict:
    ip = resolve_host_ipv4(host)
    if not ip:
        return {
            "level": "ok",
            "ip": None,
            "reasons": ["unresolved_host"],
            "summaries": ["не удалось резолвить IP хоста"],
        }
    level = index.match_ip(ip) if index and index.ready else "ok"
    reasons = []
    summaries = []
    if level == "blocked":
        reasons.append("in_rkn_dump")
        summaries.append(f"IP {ip} есть в актуальном dump РКН (реестр)")
    elif level == "at_risk":
        reasons.append("slash24_neighbour_in_dump")
        summaries.append(
            f"IP {ip} нет в dump, но в той же /24 уже есть заблокированные адреса"
        )
    return {"level": level, "ip": ip, "reasons": reasons, "summaries": summaries}


def check_server_handshakes(ssh, protocols: dict, stale_hours: float = 6.0) -> dict:
    """SSH into server and inspect awg containers for stale handshakes."""
    reasons = []
    summaries = []
    details = []
    for proto, container in AWG_CONTAINERS.items():
        if proto not in (protocols or {}):
            continue
        out = ""
        for tool in ("awg", "wg"):
            cmd = f"docker exec {container} {tool} show all 2>/dev/null"
            try:
                if hasattr(ssh, "run_sudo_command"):
                    stdout, _err, code = ssh.run_sudo_command(cmd, timeout=30)
                else:
                    stdout, _err, code = ssh.run_command(cmd, timeout=30)
            except Exception as e:
                details.append(f"{proto}:ssh_error:{e}")
                stdout, code = "", 1
            if code == 0 and stdout:
                out = stdout
                break
        if not out:
            continue
        peers = parse_awg_show(out)
        meta = load_awg_clients_meta(ssh, container)
        names = {k: (v.get("name") or "") for k, v in meta.items() if v.get("name")}
        lifetime = {k: int(v.get("lifetime_bytes") or 0) for k, v in meta.items()}
        sym = evaluate_handshake_symptom(
            peers,
            stale_hours=stale_hours,
            name_by_key=names,
            lifetime_bytes_by_key=lifetime,
        )
        if sym:
            line = humanize_handshake_symptom(proto, sym)
            reasons.append(
                f"{proto}:{sym.get('code')}:{sym['stale_count']}_peers"
            )
            summaries.append(line)
            details.append({
                "protocol": proto,
                "container": container,
                "symptom": sym,
            })
    level = "at_risk" if reasons else "ok"
    return {
        "level": level,
        "reasons": reasons,
        "summaries": summaries,
        "details": details,
    }


def merge_levels(*levels: str) -> str:
    best = "ok"
    for lv in levels:
        if _LEVEL_RANK.get(lv, 0) > _LEVEL_RANK.get(best, 0):
            best = lv
    return best
