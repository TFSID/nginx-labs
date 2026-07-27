"""listeners/http.py — HTTP callback listener."""
from __future__ import annotations

import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from core.exploit import kill_port


def _log(msg: str, level: str = "info"):
    try:
        from ui.output import log
        log(msg, level)
    except Exception:
        print(f"[{level}] {msg}")


def _listen_http(bind_ip: str, bind_port: int, state: dict, timeout: int, verbose: bool):
    """HTTP callback listener — captures POST requests with command output."""
    try:
        kill_port(bind_port)

        class HTTPCaptureHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                timestamp = datetime.now().isoformat()
                source = f"{self.client_address[0]}:{self.client_address[1]}"
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len) if content_len else b""
                decoded = body.decode("utf-8", errors="replace")
                pkt = {
                    "timestamp": timestamp, "type": "http", "source": source,
                    "method": "POST", "path": self.path,
                    "raw": decoded[:500], "decoded": decoded,
                    "size": len(body), "headers": dict(self.headers),
                }
                with state["lock"]:
                    state["packets"].append(pkt)
                print(f"[HTTP] {timestamp[:19]} <- {source} POST {self.path} ({len(body)} bytes)")
                if verbose or decoded:
                    for line in decoded.strip().split("\n")[:10]:
                        print(f"       {line}")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def do_GET(self):
                timestamp = datetime.now().isoformat()
                source = f"{self.client_address[0]}:{self.client_address[1]}"
                pkt = {
                    "timestamp": timestamp, "type": "http", "source": source,
                    "method": "GET", "path": self.path,
                    "raw": self.path, "decoded": self.path, "size": 0,
                }
                with state["lock"]:
                    state["packets"].append(pkt)
                print(f"[HTTP] {timestamp[:19]} <- {source} GET {self.path}")
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        srv = HTTPServer((bind_ip, bind_port), HTTPCaptureHandler)
        srv.timeout = 1
        start_time = time.time()
        while state["running"]:
            srv.handle_request()
            if timeout > 0 and (time.time() - start_time) > timeout:
                break
        srv.server_close()
    except Exception as e:
        _log(f"HTTP listener failed: {e}", "err")
