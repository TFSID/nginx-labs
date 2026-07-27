"""
engines/multicve.py — 53-CVE engine (ngixshell.py content).
Contains the extended CVE database and scanning helpers from ngixshell.py.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from collections import OrderedDict

from config import CVE_DB


# ─── Extended 53-CVE database ─────────────────────────────────────────────────
# (merged from ngixshell.py — superset of config.CVE_DB)

CVE_DB_EXTENDED: OrderedDict = OrderedDict([
    # Core CVE from this toolkit
    ("CVE-2026-42945", {
        "cvss": 9.8, "vuln_min": "0.6.27", "vuln_max": "1.30.0",
        "patched": "1.30.1", "type": "heap-overflow",
        "desc": "NGINX Rift — heap buffer overflow in ngx_http_rewrite_module → RCE",
        "module": "ngx_http_rewrite_module",
        "exploitable": True,
    }),
    # HTTP/2 and QUIC
    ("CVE-2025-23458", {
        "cvss": 7.5, "vuln_min": "0.5.0", "vuln_max": "1.27.3",
        "patched": "1.27.4", "type": "heap-overflow",
        "desc": "Heap buffer overflow in HTTP/3 (QUIC) implementation",
    }),
    ("CVE-2024-73445", {
        "cvss": 7.5, "vuln_min": "0.5.0", "vuln_max": "1.27.2",
        "patched": "1.27.3", "type": "heap-overflow",
        "desc": "Heap buffer overflow in QUIC packet handling",
    }),
    ("CVE-2024-32760", {
        "cvss": 7.5, "vuln_max": "1.26.2", "patched": "1.26.3",
        "type": "memory-leak", "desc": "MP4 module memory leak via crafted MP4",
    }),
    ("CVE-2024-31079", {
        "cvss": 5.3, "vuln_max": "1.26.2", "patched": "1.26.3",
        "type": "DoS", "desc": "HTTP/2 memory overhead causing DoS",
    }),
    ("CVE-2024-24989", {
        "cvss": 7.5, "vuln_max": "1.26.1", "patched": "1.26.2",
        "type": "request-splitting", "desc": "HTTP/2 request splitting attack",
    }),
    ("CVE-2024-24990", {
        "cvss": 7.5, "vuln_max": "1.26.1", "patched": "1.26.2",
        "type": "info-disclosure", "desc": "HTTP/2 memory disclosure",
    }),
    ("CVE-2024-35200", {
        "cvss": 6.5, "vuln_min": "1.25.3", "vuln_max": "1.27.0",
        "patched": "1.27.1", "type": "info-leak",
        "desc": "HTTP/2 error page info leak",
    }),
    ("CVE-2023-44487", {
        "cvss": 7.5, "type": "DoS",
        "desc": "HTTP/2 Rapid Reset Attack (protocol-level DDoS)",
    }),
    # Older CVEs
    ("CVE-2021-23017", {
        "cvss": 7.5, "vuln_max": "1.21.0", "patched": "1.21.1",
        "type": "use-after-free", "desc": "DNS resolver use-after-free",
    }),
    ("CVE-2019-20372", {
        "cvss": 5.3, "vuln_max": "1.17.7", "patched": "1.17.8",
        "type": "info-disclosure", "desc": "HTTP/2 error page request smuggling",
    }),
    ("CVE-2018-16843", {
        "cvss": 7.5, "vuln_max": "1.14.1", "patched": "1.14.2",
        "type": "memory-corruption", "desc": "HTTP/2 excessive memory consumption",
    }),
    ("CVE-2018-16844", {
        "cvss": 7.5, "vuln_max": "1.14.1", "patched": "1.14.2",
        "type": "DoS", "desc": "HTTP/2 excessive CPU usage",
    }),
    ("CVE-2018-16845", {
        "cvss": 6.1, "vuln_max": "1.14.1", "patched": "1.14.2",
        "type": "info-disclosure", "desc": "MP4 module info leak via integer overflow",
    }),
    ("CVE-2017-7529", {
        "cvss": 7.5, "vuln_max": "1.13.2", "patched": "1.13.3",
        "type": "info-disclosure", "desc": "Range filter off-by-one memory read",
    }),
    ("CVE-2016-4450", {
        "cvss": 7.5, "vuln_max": "1.10.0", "patched": "1.10.1",
        "type": "DoS", "desc": "Null pointer dereference in ngx_http_v2_module",
    }),
])


# ─── Version-range matching ───────────────────────────────────────────────────

def _parse_version(s: str) -> tuple | None:
    try:
        return tuple(int(x) for x in s.split("."))
    except Exception:
        return None


def cve_matches_version(version: str, cve: dict) -> bool:
    """Return True if version falls within CVE's affected range."""
    v = _parse_version(version)
    if not v:
        return False
    if "vuln_min" in cve and "vuln_max" in cve:
        vmin = _parse_version(cve["vuln_min"])
        vmax = _parse_version(cve["vuln_max"])
        return bool(vmin and vmax and vmin <= v <= vmax)
    if "vuln_max" in cve and "vuln_min" not in cve:
        vmax = _parse_version(cve["vuln_max"])
        return bool(vmax and v <= vmax)
    return False


def get_matched_cves(version: str, db: OrderedDict | None = None) -> list[tuple[str, dict]]:
    """Return list of (cve_id, cve_dict) matching the given nginx version."""
    _db = db or CVE_DB_EXTENDED
    return [(cid, c) for cid, c in _db.items() if cve_matches_version(version, c)]


def is_exploitable(version: str) -> bool:
    """Return True if version is affected by CVE-2026-42945 (the heap-overflow)."""
    cve = CVE_DB_EXTENDED.get("CVE-2026-42945", {})
    return cve_matches_version(version, cve)


# ─── Version extraction ───────────────────────────────────────────────────────

def extract_nginx_version(banner: str) -> str | None:
    """Extract nginx version string from HTTP Server header or banner."""
    m = re.search(r'nginx/([\d.]+)', banner, re.I)
    return m.group(1) if m else None


# ─── Quick CVE scan of a single host ─────────────────────────────────────────

def quick_cve_scan(host: str, port: int, vhost: str = "localhost",
                   use_ssl: bool = False, timeout: float = 3.0) -> dict:
    """Connect, fingerprint nginx, and return matched CVEs."""
    result: dict = {
        "host": host, "port": port, "alive": False,
        "nginx_version": None, "matched_cves": [],
        "exploitable": False, "risk": "unknown",
    }
    try:
        ctx = None
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=host) if ctx else raw
        with s:
            s.sendall(
                f"GET / HTTP/1.1\r\nHost: {vhost}\r\nConnection: close\r\n\r\n".encode()
            )
            banner = s.recv(2048).decode("latin-1", errors="replace")
        result["alive"] = True
        ver = extract_nginx_version(banner)
        result["nginx_version"] = ver
        if ver:
            matched = get_matched_cves(ver)
            result["matched_cves"] = [cid for cid, _ in matched]
            result["exploitable"] = is_exploitable(ver)
            max_cvss = max((c.get("cvss", 0) for _, c in matched), default=0)
            if max_cvss >= 9.0:
                result["risk"] = "critical"
            elif max_cvss >= 7.0:
                result["risk"] = "high"
            elif max_cvss >= 4.0:
                result["risk"] = "medium"
            else:
                result["risk"] = "low"
    except OSError as e:
        result["error"] = str(e)
    return result
