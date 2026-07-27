"""
engines/proxies.py — SOCKS5 proxy support placeholder.
"""
from __future__ import annotations

import socket


def socks5_connect(proxy_host: str, proxy_port: int,
                   dest_host: str, dest_port: int,
                   username: str | None = None,
                   password: str | None = None) -> socket.socket:
    """
    Open a raw TCP connection through a SOCKS5 proxy.
    No external dependencies required.
    """
    s = socket.create_connection((proxy_host, proxy_port), timeout=10)

    # Greeting
    if username and password:
        s.sendall(b"\x05\x02\x00\x02")  # SOCKS5, 2 methods: no-auth + user/pass
    else:
        s.sendall(b"\x05\x01\x00")      # SOCKS5, 1 method: no-auth

    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 0x05:
        s.close()
        raise ConnectionError(f"SOCKS5 handshake failed: {resp!r}")

    method = resp[1]
    if method == 0x02:  # username/password auth required
        if not username or not password:
            s.close()
            raise ConnectionError("SOCKS5 proxy requires username/password")
        auth_pkt = (
            b"\x01"
            + len(username).to_bytes(1, "big") + username.encode()
            + len(password).to_bytes(1, "big") + password.encode()
        )
        s.sendall(auth_pkt)
        auth_resp = s.recv(2)
        if auth_resp[1] != 0x00:
            s.close()
            raise ConnectionError("SOCKS5 authentication failed")
    elif method == 0xFF:
        s.close()
        raise ConnectionError("SOCKS5: no acceptable auth method")

    # CONNECT request
    host_bytes = dest_host.encode()
    connect_pkt = (
        b"\x05\x01\x00\x03"
        + len(host_bytes).to_bytes(1, "big") + host_bytes
        + dest_port.to_bytes(2, "big")
    )
    s.sendall(connect_pkt)
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0x00:
        s.close()
        raise ConnectionError(f"SOCKS5 CONNECT failed: {resp!r}")

    return s
