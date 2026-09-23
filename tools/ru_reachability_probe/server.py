#!/usr/bin/env python3
"""Minimal RU-egress reachability probe for awg-fork RKN monitor.

Deploy on a Russian VPS (e.g. Timeweb) so the panel can ask: "can this
vantage reach host:TCP and host:UDP?".

POST /v1/probe
  {"targets":[{"host":"1.2.3.4","tcp_ports":[22],"udp_ports":[19999]}]}
→ {"egress_ip":"…","results":[{"host","proto","port","ok","ms","error"}]}

Optional: PROBE_TOKEN env → require Authorization: Bearer <token>.
"""

from __future__ import annotations

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen

LISTEN = os.environ.get("PROBE_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("PROBE_PORT", "8099"))
TOKEN = (os.environ.get("PROBE_TOKEN") or "").strip()
TCP_TIMEOUT = float(os.environ.get("PROBE_TCP_TIMEOUT", "5"))
UDP_TIMEOUT = float(os.environ.get("PROBE_UDP_TIMEOUT", "3"))


def _egress_ip() -> str:
    for url in (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ):
        try:
            with urlopen(url, timeout=5) as resp:
                ip = resp.read().decode("utf-8", errors="replace").strip()
                if ip and " " not in ip and len(ip) < 64:
                    return ip
        except Exception:
            continue
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def probe_tcp(host: str, port: int) -> dict:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            ms = int((time.monotonic() - t0) * 1000)
            return {"host": host, "proto": "tcp", "port": port, "ok": True, "ms": ms}
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        return {
            "host": host,
            "proto": "tcp",
            "port": port,
            "ok": False,
            "ms": ms,
            "error": str(e),
        }


def probe_udp(host: str, port: int) -> dict:
    """Send one UDP datagram. ok=True means the send succeeded (not that a reply came)."""
    t0 = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UDP_TIMEOUT)
        s.sendto(b"awg-ru-probe", (host, port))
        try:
            s.recvfrom(64)  # optional pong from panel echo
            replied = True
        except socket.timeout:
            replied = False
        s.close()
        ms = int((time.monotonic() - t0) * 1000)
        return {
            "host": host,
            "proto": "udp",
            "port": port,
            "ok": True,
            "ms": ms,
            "replied": replied,
        }
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        return {
            "host": host,
            "proto": "udp",
            "port": port,
            "ok": False,
            "ms": ms,
            "error": str(e),
        }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[probe] {self.address_string()} {fmt % args}")

    def _auth_ok(self) -> bool:
        if not TOKEN:
            return True
        hdr = self.headers.get("Authorization") or ""
        return hdr.strip() == f"Bearer {TOKEN}"

    def _json(self, code: int, payload: dict):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path in ("/", "/health", "/healthz"):
            self._json(200, {"ok": True, "egress_ip": _egress_ip()})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/v1/probe":
            self._json(404, {"error": "not_found"})
            return
        if not self._auth_ok():
            self._json(401, {"error": "unauthorized"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            self._json(413, {"error": "too_large"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") if length else "{}")
        except Exception:
            self._json(400, {"error": "bad_json"})
            return
        targets = body.get("targets") or []
        if not isinstance(targets, list) or len(targets) > 32:
            self._json(400, {"error": "bad_targets"})
            return
        results = []
        for t in targets:
            if not isinstance(t, dict):
                continue
            host = (t.get("host") or "").strip()
            if not host:
                continue
            for p in t.get("tcp_ports") or []:
                try:
                    results.append(probe_tcp(host, int(p)))
                except Exception as e:
                    results.append(
                        {"host": host, "proto": "tcp", "port": p, "ok": False, "error": str(e)}
                    )
            for p in t.get("udp_ports") or []:
                try:
                    results.append(probe_udp(host, int(p)))
                except Exception as e:
                    results.append(
                        {"host": host, "proto": "udp", "port": p, "ok": False, "error": str(e)}
                    )
        self._json(200, {"egress_ip": _egress_ip(), "results": results})


def main():
    httpd = ThreadingHTTPServer((LISTEN, PORT), Handler)
    print(f"ru-reachability-probe on {LISTEN}:{PORT} token={'yes' if TOKEN else 'no'}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
