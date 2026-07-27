"""
recon/audit.py — HTTP security-header and TLS audits.
"""
from __future__ import annotations

import re
import socket
import warnings

from config import SECURITY_HEADERS
from core.spray import wrap_if_ssl


def audit_headers(host: str, port: int, vhost: str = "l",
                  use_ssl: bool = False) -> dict:
    """Check for standard security headers."""
    result: dict = {}
    try:
        sock = socket.create_connection((host, port), timeout=5)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(
                f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode()
            )
            data = s.recv(8192)
            raw = data.decode("latin-1", errors="replace")
            for hdr, desc in SECURITY_HEADERS:
                m = re.search(rf'^{hdr}:\s*(.+)$', raw, re.I | re.M)
                result[hdr] = {
                    "present": bool(m),
                    "value": m.group(1).strip() if m else None,
                    "description": desc,
                }
    except OSError as e:
        return {"error": str(e)}
    return result


def tls_audit(host: str, port: int, vhost: str | None = None) -> dict:
    """Check which TLS versions (1.0–1.3) the server accepts."""
    import ssl as _ssl
    result: dict = {}
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    server_name = vhost or host

    versions = []
    for name, attr in [
        ("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3"),
    ]:
        v = getattr(_ssl.TLSVersion, attr, None)
        if v is not None:
            versions.append((name, v))

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for ver_name, ver_const in versions:
            try:
                ctx.minimum_version = ver_const
                ctx.maximum_version = ver_const
                with socket.create_connection((host, port), timeout=3) as s:
                    with ctx.wrap_socket(s, server_hostname=server_name):
                        result[ver_name] = True
            except Exception:
                result[ver_name] = False
    return result
