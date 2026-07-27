"""modes/listen.py — Standalone listener-only mode."""
from __future__ import annotations
import sys
import threading
import time
from datetime import datetime

from listeners.tcp import _listen_tcp
from listeners.http import _listen_http
from listeners.dns import _listen_dns
from listeners.websocket import _listen_websocket

try:
    from ui.tui import _GRN, _RST
except ImportError:
    _GRN = _RST = ""


def mode_listen_only(listen_type: str = "tcp", listen_ip: str = "0.0.0.0",
                     listen_port: int = 0, timeout: int = 0,
                     output_file: str | None = None, verbose: bool = False) -> dict:
    """
    Standalone listener mode: capture C2 callbacks from already-exploited targets.

    listen_type: "tcp" | "http" | "dns" | "ws" | "all"
    listen_port: 0 = auto (tcp=4444, http=8888, dns=53, ws=9999)
    timeout: 0 = infinite (Ctrl+C to stop)
    """
    result = {
        "listen_type": listen_type, "listen_ip": listen_ip,
        "listen_port": listen_port, "timeout": timeout,
        "captured_count": 0, "packets": [], "errors": [],
        "start_time": datetime.now().isoformat(),
    }

    default_ports = {"tcp": 4444, "http": 8888, "dns": 53, "ws": 9999}
    listeners_to_start = ["tcp", "http", "dns", "ws"] if listen_type == "all" else [listen_type]

    listener_threads: list[threading.Thread] = []
    listener_states: dict[str, dict] = {}

    _fn_map = {"tcp": _listen_tcp, "http": _listen_http,
               "dns": _listen_dns, "ws": _listen_websocket}

    for ltype in listeners_to_start:
        port = listen_port if listen_port else default_ports.get(ltype, 8888)
        state: dict = {
            "type": ltype, "port": port, "packets": [],
            "running": True, "lock": threading.Lock(),
        }
        listener_states[ltype] = state
        fn = _fn_map.get(ltype)
        if fn is None:
            continue
        t = threading.Thread(
            target=fn, args=(listen_ip, port, state, timeout, verbose),
            daemon=True, name=f"listener-{ltype}-{port}",
        )
        listener_threads.append(t)
        t.start()
        print(f"[+] Started {ltype.upper()} listener on {listen_ip}:{port}")

    try:
        if timeout > 0:
            end_time = time.time() + timeout
            while time.time() < end_time and listener_threads:
                listener_threads = [t for t in listener_threads if t.is_alive()]
                time.sleep(0.5)
        else:
            print(f"\n{_GRN}Listening for callbacks... (Press Ctrl+C to stop){_RST}\n")
            while listener_threads:
                listener_threads = [t for t in listener_threads if t.is_alive()]
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Listener interrupted by user")

    for ltype, state in listener_states.items():
        state["running"] = False
        result["packets"].extend(state["packets"])
        result["captured_count"] += len(state["packets"])

    result["end_time"] = datetime.now().isoformat()

    if output_file and result["packets"]:
        try:
            with open(output_file, "w") as f:
                for pkt in result["packets"]:
                    f.write(f"[{pkt['timestamp']}] {pkt['type'].upper()} from {pkt['source']}\n")
                    if pkt.get("decoded"):
                        f.write(f"  Decoded: {pkt['decoded']}\n")
                    f.write("\n")
            print(f"[+] Captured packets saved to {output_file}")
        except Exception as e:
            result["errors"].append(str(e))

    return result
