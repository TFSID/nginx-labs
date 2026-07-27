"""
NGINX Rift — CVE-2026-42945 Super Toolkit
Modular package. Import the submodule you need, or use main.py as entry point.
"""
from config import VERSION, BANNER, CVE_DB, KNOWN_BUILDS

from core.exploit import mode_exploit, mode_check, ExploitResult
from modes.dos import mode_dos
from modes.probe import mode_probe_cmd, mode_curl_only
from modes.listen import mode_listen_only
from recon.scanner import detect_service, scan_subnet, is_version_vulnerable

__version__ = VERSION
__all__ = [
    "mode_exploit", "mode_check", "ExploitResult",
    "mode_dos", "mode_probe_cmd", "mode_curl_only", "mode_listen_only",
    "detect_service", "scan_subnet", "is_version_vulnerable",
    "VERSION", "BANNER", "CVE_DB", "KNOWN_BUILDS",
]
