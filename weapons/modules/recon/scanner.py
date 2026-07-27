"""
recon/scanner.py — Service detection, subnet scanning, SSH scanning, CVE matching.
"""
from __future__ import annotations

import re
import socket
import subprocess

from config import SECURITY_HEADERS, CVE_DB
from core.spray import server_alive, wrap_if_ssl


def log(msg: str, level: str = "info"):
    from ui.output import log as _log  # type: ignore[import]
    _log(msg, level)


# ─── detect_service ───────────────────────────────────────────────────────────

def detect_service(host: str, port: int, timeout: float = 3,
                   vhost: str = "l", use_ssl: bool = False) -> dict:
    info = {"host": host, "port": port, "alive": False, "use_ssl": use_ssl, "vhost": vhost}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        with wrap_if_ssl(sock, host, use_ssl) as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost:{vhost}\r\nConnection:close\r\n\r\n".encode())
            data = s.recv(4096)
            info["alive"] = True
            raw = data.decode("latin-1", errors="replace")

            m = re.search(r'Server:\s*(\S+)', raw, re.I)
            info["server"] = m.group(1) if m else "unknown"

            m = re.search(r'nginx/([\d.]+)', raw, re.I)
            info["nginx_version"] = m.group(1) if m else None

            m = re.search(r'HTTP/[\d.]+\s+(\d+)', raw)
            info["status"] = int(m.group(1)) if m else 0

            if info["status"] in (301, 302, 307, 308):
                m = re.search(r'Location:\s*(\S+)', raw, re.I)
                if m:
                    info["redirect"] = m.group(1)

            info["security_headers"] = {}
            for hdr, _ in SECURITY_HEADERS:
                m = re.search(rf'^{hdr}:\s*(.+)$', raw, re.I | re.M)
                info["security_headers"][hdr] = m.group(1).strip() if m else None

            info["raw_headers"] = raw.split("\r\n\r\n")[0] if "\r\n\r\n" in raw else raw[:500]
    except OSError as e:
        info["error"] = str(e)
    return info


# ─── scan_subnet ──────────────────────────────────────────────────────────────

def scan_subnet(subnet: str, port: int, workers: int = 20, timeout: float = 2) -> list[str]:
    """CIDR subnet host discovery (gagaltotal style)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import ipaddress

    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
    except ValueError:
        log(f"Invalid subnet: {subnet}", "err")
        return []

    log(f"Scanning {len(hosts)} hosts in {subnet} on port {port}...", "info")
    live: list[str] = []

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


# ─── SSH helpers ──────────────────────────────────────────────────────────────

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
    """SSH into host and gather nginx info (gagaltotal style)."""
    if not password and not key_path:
        return {"error": "no auth method (provide password or key_path)"}
    result: dict = {"host": host, "os": None, "nginx_version": None,
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


# ─── CVE matching ─────────────────────────────────────────────────────────────

def _cve_matches(version: str, cve: dict) -> bool:
    """Return True if version falls within a single CVE entry's affected range."""
    def parse_v(s: str):
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


# ─── Bulk fingerprint check ───────────────────────────────────────────────────

def bulk_fingerprint_check(targets: list[str], workers: int = 20,
                           output: str | None = None) -> list[dict]:
    """Concurrent fingerprint + vuln + WAF check across a list of targets."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from recon.nginx_config import detect_waf  # type: ignore[import]
    from ui.output import generate_html_scan_report, generate_json_report  # type: ignore[import]

    def parse_target_local(s: str):
        from config import DEFAULT_PORT
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

    def check_one(raw: str) -> dict:
        target = raw.strip()
        if not target or target.startswith("#"):
            return {}
        parsed = parse_target_local(target)
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
                log(
                    f"{r['target']:28s}  nginx/{str(r.get('nginx_version', '?')):10s}"
                    f"  {label}  cves=[{cves}]  waf=[{waf}]",
                    level,
                )
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
