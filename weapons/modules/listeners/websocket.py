"""listeners/websocket.py — WebSocket exfil listener (raw HTTP-upgrade, stdlib only)."""
from __future__ import annotations

import base64
import hashlib
import socket
import struct
import time
from datetime import datetime


_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _log(msg: str, level: str = "info"):
    try:
        from ui.output import log
        log(msg, level)
    except Exception:
        print(f"[{level}] {msg}")


def _ws_handshake(conn: socket.socket) -> bool:
    """Perform WebSocket upgrade handshake, return True if successful."""
    try:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = conn.recv(2048)
            if not chunk:
                return False
            raw += chunk

        headers_raw = raw.decode("latin-1", errors="replace")
        ws_key = None
        for line in headers_raw.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                ws_key = line.split(":", 1)[1].strip()
                break

        if not ws_key:
            return False

        accept = base64.b64encode(
            hashlib.sha1((ws_key + _WS_MAGIC).encode()).digest()
        ).decode()

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        conn.sendall(response.encode())
        return True
    except Exception:
        return False


def _ws_recv_frame(conn: socket.socket) -> bytes | None:
    """Read one WebSocket frame and return unmasked payload."""
    try:
        header = b""
        while len(header) < 2:
            chunk = conn.recv(2 - len(header))
            if not chunk:
                return None
            header += chunk

        masked = bool(header[1] & 0x80)
        payload_len = header[1] & 0x7F

        if payload_len == 126:
            ext = b""
            while len(ext) < 2:
                c = conn.recv(2 - len(ext))
                if not c:
                    return None
                ext += c
            payload_len = struct.unpack("!H", ext)[0]
        elif payload_len == 127:
            ext = b""
            while len(ext) < 8:
                c = conn.recv(8 - len(ext))
                if not c:
                    return None
                ext += c
            payload_len = struct.unpack("!Q", ext)[0]

        mask_key = b""
        if masked:
            while len(mask_key) < 4:
                c = conn.recv(4 - len(mask_key))
                if not c:
                    return None
                mask_key += c

        payload = b""
        while len(payload) < payload_len:
            chunk = conn.recv(min(4096, payload_len - len(payload)))
            if not chunk:
                return None
            payload += chunk

        if masked:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        return payload
    except Exception:
        return None


def _listen_websocket(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """WebSocket exfil listener — accepts upgrade connections and captures frames."""
    try:
        from core.exploit import kill_port
        kill_port(bind_port)

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.listen(10)
        srv.settimeout(1)

        start_time = time.time()
        while state["running"]:
            try:
                conn, addr = srv.accept()
                conn.settimeout(30)
                timestamp = datetime.now().isoformat()
                source = f"{addr[0]}:{addr[1]}"

                if not _ws_handshake(conn):
                    conn.close()
                    continue

                data = b""
                while True:
                    frame = _ws_recv_frame(conn)
                    if frame is None:
                        break
                    data += frame
                    if len(data) > 65536:
                        break

                decoded = data.decode("utf-8", errors="replace")
                pkt = {
                    "timestamp": timestamp, "type": "websocket",
                    "source": source, "raw": decoded[:500],
                    "decoded": decoded, "size": len(data),
                }
                with state["lock"]:
                    state["packets"].append(pkt)
                print(f"[WS]  {timestamp[:19]} <- {source} ({len(data)} bytes)")
                if verbose and decoded:
                    for line in decoded.strip().split("\n")[:5]:
                        print(f"      {line}")
                conn.close()
            except socket.timeout:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    break
            except Exception as e:
                if state["running"]:
                    _log(f"WebSocket listener error: {e}", "warn")

        srv.close()
    except Exception as e:
        _log(f"WebSocket listener failed: {e}", "err")
