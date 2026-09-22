"""RKN (Roskomnadzor) blocklist monitor helpers.

Downloads/caches the public zapret-info dump, matches server IPs against it,
flags /24 neighbours as at-risk, and parses AmneziaWG `awg show` output for
stale-handshake symptoms (DPI path blocks that are not yet in the registry).
"""

from __future__ import annotations

import gzip
import ipaddress
import logging
import os
import re
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
    """In-memory IPv4 index built from zapret-info dump.csv[.gz]."""

    def __init__(self):
        self.exact: set[int] = set()
        self.networks: list[ipaddress.IPv4Network] = []
        self.blocked_slash24: set[int] = set()  # network_address >> 8
        self.loaded_at: float = 0.0
        self.source: str = ""
        self.entry_count: int = 0

    @property
    def ready(self) -> bool:
        return bool(self.exact or self.networks)

    def _add_ip(self, ip: ipaddress.IPv4Address):
        n = int(ip)
        self.exact.add(n)
        self.blocked_slash24.add(n >> 8)

    def _add_net(self, net: ipaddress.IPv4Network):
        if net.prefixlen == 32:
            self._add_ip(net.network_address)
            return
        self.networks.append(net)
        # Mark every /24 covered by this prefix as "neighbour pressure".
        step = 256
        start = int(net.network_address)
        end = int(net.broadcast_address)
        for addr in range(start & ~0xFF, end + 1, step):
            self.blocked_slash24.add(addr >> 8)

    def add_token(self, token: str):
        token = (token or "").strip()
        if not token:
            return
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    self._add_net(net)
                    self.entry_count += 1
            else:
                ip = ipaddress.ip_address(token)
                if isinstance(ip, ipaddress.IPv4Address):
                    self._add_ip(ip)
                    self.entry_count += 1
        except ValueError:
            return

    def match_ip(self, ip_str: str) -> str:
        """Return 'blocked', 'at_risk' (/24 neighbour), or 'ok'."""
        try:
            ip = ipaddress.ip_address((ip_str or "").strip())
        except ValueError:
            return "ok"
        if not isinstance(ip, ipaddress.IPv4Address):
            return "ok"
        n = int(ip)
        if n in self.exact:
            return "blocked"
        for net in self.networks:
            if ip in net:
                return "blocked"
        if (n >> 8) in self.blocked_slash24:
            return "at_risk"
        return "ok"


_index: Optional[RknDumpIndex] = None
_index_lock = __import__("threading").RLock()


def cache_dir_for_data_file(data_file: str) -> str:
    base = os.path.dirname(os.path.abspath(data_file)) or "."
    return os.path.join(base, "rkn_cache")


def _parse_dump_bytes(raw: bytes, source: str) -> RknDumpIndex:
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="ignore")
    idx = RknDumpIndex()
    idx.source = source
    for line in text.splitlines():
        if not line or line.startswith("Updated:") or line.lower().startswith("ip;"):
            continue
        # dump.csv: first field is "ip | ip | cidr", semicolon-separated columns
        first = line.split(";", 1)[0]
        for part in first.split("|"):
            idx.add_token(part.strip())
    # Keep networks sorted by prefix length (more specific first) for faster hit
    idx.networks.sort(key=lambda n: n.prefixlen, reverse=True)
    idx.loaded_at = time.time()
    return idx


def load_dump_from_cache(cache_dir: str) -> Optional[RknDumpIndex]:
    path = os.path.join(cache_dir, "dump.csv.gz")
    alt = os.path.join(cache_dir, "dump.csv")
    try:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                return _parse_dump_bytes(f.read(), path)
        if os.path.isfile(alt):
            with open(alt, "rb") as f:
                return _parse_dump_bytes(f.read(), alt)
    except Exception as e:
        logger.warning("RKN cache load failed: %s", e)
    return None


def download_dump(url: str, cache_dir: str, timeout: int = 120) -> RknDumpIndex:
    os.makedirs(cache_dir, exist_ok=True)
    req = Request(url, headers={"User-Agent": "awg-fork-rkn-monitor/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    dest = os.path.join(
        cache_dir,
        "dump.csv.gz" if raw[:2] == b"\x1f\x8b" or url.endswith(".gz") else "dump.csv",
    )
    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, dest)
    meta = os.path.join(cache_dir, "meta.txt")
    with open(meta, "w", encoding="utf-8") as f:
        f.write(f"url={url}\nfetched_at={time.time()}\nsize={len(raw)}\n")
    return _parse_dump_bytes(raw, dest)


def ensure_dump_index(
    cache_dir: str,
    url: str = DEFAULT_DUMP_URL,
    refresh_seconds: int = 14400,
    force: bool = False,
) -> RknDumpIndex:
    """Return shared index, refreshing from network when stale/missing."""
    global _index
    with _index_lock:
        now = time.time()
        if (
            not force
            and _index is not None
            and _index.ready
            and (now - _index.loaded_at) < refresh_seconds
        ):
            return _index

        cached = load_dump_from_cache(cache_dir)
        if (
            not force
            and cached is not None
            and cached.ready
            and (now - os.path.getmtime(cached.source)) < refresh_seconds
        ):
            _index = cached
            logger.info(
                "RKN dump loaded from cache: %s exact=%s nets=%s",
                cached.source,
                len(cached.exact),
                len(cached.networks),
            )
            return _index

        try:
            _index = download_dump(url, cache_dir)
            logger.info(
                "RKN dump downloaded: exact=%s nets=%s slash24=%s",
                len(_index.exact),
                len(_index.networks),
                len(_index.blocked_slash24),
            )
            return _index
        except Exception as e:
            logger.error("RKN dump download failed: %s", e)
            if cached is not None and cached.ready:
                _index = cached
                return _index
            if _index is not None and _index.ready:
                return _index
            raise


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
            cur = {"public_key": raw.split(":", 1)[1].strip(), "handshake_age": None, "transfer": 0}
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


def evaluate_handshake_symptom(
    peers: list[dict],
    stale_hours: float = 6.0,
) -> Optional[str]:
    """Return reason string if peers look DPI-blocked; else None.

    Ignores unused peers (zero transfer, never handshaked). Requires at least
    one peer that previously exchanged traffic.
    """
    stale_sec = max(1.0, float(stale_hours)) * 3600
    active = [p for p in peers if (p.get("transfer") or 0) > 0 or p.get("handshake_age") is not None]
    if not active:
        return None
    # Peers that ever had traffic are the signal; if all of those are stale → risk
    with_history = [p for p in peers if (p.get("transfer") or 0) > 0]
    if not with_history:
        return None
    for p in with_history:
        age = p.get("handshake_age")
        if age is not None and age < stale_sec:
            return None
    oldest = max((p.get("handshake_age") or 10**9) for p in with_history)
    if oldest >= stale_sec:
        hours = round(oldest / 3600, 1)
        return f"no_handshake:{len(with_history)}_peers_stale>={hours}h"
    return None


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
        return {"level": "ok", "ip": None, "reasons": ["unresolved_host"]}
    level = index.match_ip(ip) if index and index.ready else "ok"
    reasons = []
    if level == "blocked":
        reasons.append("in_rkn_dump")
    elif level == "at_risk":
        reasons.append("slash24_neighbour_in_dump")
    return {"level": level, "ip": ip, "reasons": reasons}


def check_server_handshakes(ssh, protocols: dict, stale_hours: float = 6.0) -> dict:
    """SSH into server and inspect awg containers for stale handshakes."""
    reasons = []
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
        reason = evaluate_handshake_symptom(peers, stale_hours=stale_hours)
        if reason:
            reasons.append(f"{proto}:{reason}")
            details.append(f"{proto}:peers={len(peers)}")
    level = "at_risk" if reasons else "ok"
    return {"level": level, "reasons": reasons, "details": details}


def merge_levels(*levels: str) -> str:
    order = {"ok": 0, "at_risk": 1, "blocked": 2}
    best = "ok"
    for lv in levels:
        if order.get(lv, 0) > order.get(best, 0):
            best = lv
    return best
