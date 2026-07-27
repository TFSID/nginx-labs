"""patch/apply.py — SSH remote patching of nginx installations."""
from __future__ import annotations

from recon.scanner import _ssh_run

PATCH_COMMANDS = {
    "ubuntu": {
        "pre_check": "dpkg -l nginx 2>/dev/null | grep nginx || which nginx",
        "add_repo": ("echo 'deb https://nginx.org/packages/ubuntu/ $(lsb_release -cs) nginx' "
                     "> /etc/apt/sources.list.d/nginx.list; "
                     "curl -fsSL https://nginx.org/keys/nginx_signing.key | "
                     "gpg --dearmor -o /etc/apt/trusted.gpg.d/nginx.gpg"),
        "upgrade": "apt-get update -qq && apt-get install -y nginx=~1.30.1",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
        "pin": "apt-mark hold nginx",
    },
    "debian": {
        "upgrade": "apt-get update -qq && apt-get install -y --only-upgrade nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
    "centos": {
        "upgrade": "yum update -y nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
    "rhel": {
        "upgrade": "dnf update -y nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
    "almalinux": {
        "upgrade": "dnf update -y nginx",
        "verify": "nginx -v 2>&1",
        "reload": "nginx -t && systemctl reload nginx || nginx -s reload",
        "backup": "tar czf /tmp/nginx-backup-$(date +%Y%m%d).tar.gz /etc/nginx/",
    },
}


def patch_server(host: str, port: int, user: str, password: str | None = None,
                 key_path: str | None = None, dry_run: bool = False,
                 target_version: str = "1.30.1") -> dict:
    """SSH remote patching (gagaltotal style). Uses system ssh binary."""
    if not password and not key_path:
        return {"error": "no auth method (provide password or key_path)"}
    result = {"host": host, "status": "pending", "steps": []}

    def add_step(name: str, status: str, detail: str = ""):
        result["steps"].append({"step": name, "status": status, "detail": detail})

    def run(cmd: str, t: int = 30) -> tuple[str, str, int]:
        return _ssh_run(host, user, cmd,
                        key_path=key_path, password=password, port=port, timeout=t)

    _, err, rc = run("echo ok", t=15)
    if rc != 0:
        add_step("connect", "err", err.strip() or f"ssh exit {rc}")
        result["status"] = "failed"
        return result
    add_step("connect", "ok", f"SSH to {host}:{port} as {user}")

    out, _, _ = run("cat /etc/os-release 2>/dev/null | head -3")
    os_out = out.lower()
    distro = None
    for d in PATCH_COMMANDS:
        if d in os_out:
            distro = d
            break
    if not distro:
        out2, _, _ = run("cat /etc/redhat-release 2>/dev/null")
        rh = out2.lower()
        if "centos" in rh:       distro = "centos"
        elif "alma" in rh:       distro = "almalinux"
        elif "red hat" in rh:    distro = "rhel"
    if not distro:
        distro = "ubuntu"
    add_step("detect_os", "ok", distro)

    out, _, _ = run("nginx -v 2>&1; echo '---'; /usr/sbin/nginx -v 2>&1")
    add_step("current_version", "ok", out[:100])

    if dry_run:
        add_step("dry_run", "ok", "dry-run mode, no changes made")
        result["status"] = "dry-run"
        return result

    cmds = PATCH_COMMANDS.get(distro, PATCH_COMMANDS["ubuntu"])

    if "backup" in cmds:
        out, _, _ = run(cmds["backup"])
        add_step("backup", "ok", out[:100])

    if "upgrade" in cmds:
        add_step("upgrade", "running", f"target: {target_version}")
        out, err, _ = run(cmds["upgrade"], t=180)
        add_step("upgrade", "ok" if "error" not in err.lower() else "warn",
                 (out + err)[:200])

    if target_version:
        out, _, _ = run(f"nginx -v 2>&1 | grep {target_version}")
        verified = bool(out.strip())
        add_step("verify", "ok" if verified else "warn",
                 f"nginx -v: {target_version} {'found' if verified else 'not found'}")

    if "reload" in cmds:
        out, err, _ = run(cmds["reload"], t=30)
        add_step("reload", "ok", (out or err)[:100])

    result["status"] = "patched"
    return result
