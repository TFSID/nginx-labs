"""recon — reconnaissance sub-package."""
from recon.scanner import (
    detect_service, scan_subnet, _ssh_run, scan_ssh,
    is_version_vulnerable, _cve_matches, bulk_fingerprint_check,
)
from recon.nginx_config import check_nginx_config, detect_waf
from recon.endpoints import path_discovery
from recon.audit import audit_headers, tls_audit

__all__ = [
    "detect_service", "scan_subnet", "_ssh_run", "scan_ssh",
    "is_version_vulnerable", "_cve_matches", "bulk_fingerprint_check",
    "check_nginx_config", "detect_waf",
    "path_discovery",
    "audit_headers", "tls_audit",
]
