"""listeners/tcp.py — TCP reverse-shell listener."""
from __future__ import annotations

import socket
import time
from datetime import datetime

from core.exploit import kill_port


def _log(msg: str, level: str = "info"):
    try:
        from ui.output import log
        log(msg, level)
    except Exception:
        print(f"[{level}] {msg}")


def _listen_tcp(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """TCP reverse shell listener — captures incoming shell connections."""
    try:
        kill_port(bind_port)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, bind_port))
        srv.listen(5)
        srv.settimeout(1)

        start_time = time.time()
        while state["running"]:
            try:
                conn, addr = srv.accept()
                timestamp = datetime.now().isoformat()
                source = f"{addr[0]}:{addr[1]}"

                data = b""
                conn.settimeout(5)
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 65536:
                            break
                except socket.timeout:
                    pass

                decoded = data.decode("utf-8", errors="replace")
                pkt = {
                    "timestamp": timestamp,
                    "type": "tcp",
                    "source": source,
                    "raw": decoded[:500],
                    "decoded": decoded,
                    "size": len(data),
                }
                with state["lock"]:
                    state["packets"].append(pkt)

                print(f"[TCP] {timestamp[:19]} <- {source} ({len(data)} bytes)")
                if verbose or decoded:
                    for line in decoded.strip().split("\n")[:10]:
                        print(f"      {line}")
                conn.close()
            except socket.timeout:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    break
            except Exception as e:
                if state["running"]:
                    _log(f"TCP listener error: {e}", "warn")
    except Exception as e:
        _log(f"TCP listener failed: {e}", "err")
    finally:
        try:
            srv.close()
        except Exception:
            pass
