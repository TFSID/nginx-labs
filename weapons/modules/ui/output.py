"""
ui/output.py — Reporting functions and shared logger.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

_IS_TTY = sys.stdout.isatty()

def _c(code: str) -> str:
    return code if _IS_TTY else ""

_RST  = _c("\033[0m");  _BOLD = _c("\033[1m");  _DIM  = _c("\033[2m")
_CYAN = _c("\033[36m"); _YLW  = _c("\033[33m"); _GRN  = _c("\033[32m")
_RED  = _c("\033[31m"); _BLU  = _c("\033[34m"); _MAG  = _c("\033[35m")
_ANSI_LEVEL = {
    "info": _BLU, "ok": _GRN, "warn": _YLW, "err": _RED, "debug": _DIM,
}


def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "debug": "[D]"}
    p = prefix.get(level, "[*]")
    color = _ANSI_LEVEL.get(level, "")
    print(f"{_DIM}{ts}{_RST} {color}{p}{_RST} {msg}")


def _print_panel(content: str, title: str = "", width: int = 72):
    inner = width - 4
    t = f" {title} " if title else ""
    pad = max(0, width - 2 - len(t))
    top = f"╔{'=' * (pad // 2)}{_BOLD}{t}{_RST}{'=' * (pad - pad // 2)}╗"
    bot = f"╚{'=' * (width - 2)}╝"
    print(top)
    for line in content.splitlines():
        lp = line[:inner]
        print(f"║ {lp:<{inner}} ║")
    print(bot)


def _print_table(headers: list, rows: list, title: str = ""):
    if not rows:
        print("  (no results)")
        return
    if title:
        print(f"\n{_BOLD}  {title}{_RST}")
    cw = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    top = "┌─" + "─┬─".join("─" * w for w in cw) + "─┐"
    mid = "├─" + "─┼─".join("─" * w for w in cw) + "─┤"
    bot = "└─" + "─┴─".join("─" * w for w in cw) + "─┘"
    print(top)
    print("│ " + " │ ".join(
        (_BOLD + str(h) + _RST).ljust(cw[i] + len(_BOLD) + len(_RST))
        for i, h in enumerate(headers)
    ) + " │")
    print(mid)
    for row in rows:
        print("│ " + " │ ".join(str(row[i]).ljust(cw[i]) for i in range(len(headers))) + " │")
    print(bot)


def generate_html_scan_report(results: list[dict], out_path: str):
    vuln_count = sum(1 for r in results if r.get("vulnerable"))
    safe_count = sum(1 for r in results if r.get("vulnerable") is False)
    total = len(results)
    rows = ""
    for r in results:
        cls = "vuln" if r.get("vulnerable") else ("safe" if r.get("vulnerable") is False else "unknown")
        ver = r.get("nginx_version") or r.get("server") or "unknown"
        os_info = r.get("os", "N/A")
        rows += (
            f"<tr class='{cls}'>"
            f"<td>{r.get('host', '?')}</td><td>{ver}</td>"
            f"<td>{os_info}</td><td>{cls}</td></tr>"
        )
    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>NGINX Rift — Scan Report</title>
<style>
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;padding:2rem}}
h1{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}
th{{background:#161b22;color:#58a6ff;padding:.5rem;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:.5rem;border-bottom:1px solid #21262d}}
tr.vuln td{{border-left:3px solid #f85149}}tr.safe td{{border-left:3px solid #3fb950}}
.summary{{display:flex;gap:1rem;margin:1rem 0}}.card{{padding:1rem;border-radius:6px;background:#161b22;flex:1}}
.card h3{{margin:0 0 .3rem 0}}.num{{font-size:2rem;font-weight:700}}.green{{color:#3fb950}}.red{{color:#f85149}}
</style></head><body>
<h1>NGINX Rift — Scan Report</h1>
<div class="summary">
  <div class="card"><h3>Total</h3><div class="num">{total}</div></div>
  <div class="card"><h3>Vulnerable</h3><div class="num red">{vuln_count}</div></div>
  <div class="card"><h3>Safe</h3><div class="num green">{safe_count}</div></div>
</div>
<table><thead><tr><th>Host</th><th>Version</th><th>OS</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
    Path(out_path).write_text(html)
    log(f"Report saved: {out_path}", "ok")


def generate_json_report(data: dict, out_path: str):
    Path(out_path).write_text(json.dumps(data, indent=2, default=str))
    log(f"JSON saved: {out_path}", "ok")


def print_scan_results(results: list[dict]):
    rows = []
    for r in results:
        vuln = r.get("vulnerable")
        v_str = f"{_RED}YES{_RST}" if vuln else (f"{_GRN}NO{_RST}" if vuln is False else "?")
        rows.append([r.get("host", "?"), r.get("nginx_version", "?"), v_str])
    _print_table(["Host", "Version", "Vulnerable"], rows, title="Scan Results")
