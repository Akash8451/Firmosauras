"""Component version-candidate extraction (Task 8).

Regex-per-family over the extracted strings for the embedded-firmware components
Group 3's CVE matcher scopes to (busybox, openssl, libcurl, dropbear, uclibc,
linux kernel). Emits ``{vendor, product, version}`` tuples (SCHEMA.md §2
``version_candidates``); the vendor/product spellings line up with the family
product index in ``services/cve_matching/config.py`` so the matcher resolves them.

These are CANDIDATES — recall-biased banner/version scraping. The deterministic
CPE/embedding match + confidence tiering downstream decides what is real.
"""
from __future__ import annotations

import re
from typing import List

# (vendor, product, compiled pattern with one capture group = version).
_PATTERNS = [
    ("busybox", "busybox", re.compile(r"BusyBox\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("openssl", "openssl", re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)", re.IGNORECASE)),
    ("curl", "libcurl", re.compile(r"libcurl/(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("curl", "curl", re.compile(r"\bcurl\s+(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("dropbear", "dropbear", re.compile(r"[Dd]ropbear(?:\s+SSH)?[ _]v?(\d{4}\.\d+|\d+\.\d+)")),
    ("uclibc", "uclibc", re.compile(r"uClibc(?:-ng)?[ -]?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("linux", "linux_kernel", re.compile(r"Linux version\s+(\d+\.\d+(?:\.\d+)?)")),
]


def find_version_candidates(strings: List[str]) -> List[dict]:
    """Return de-duplicated ``{vendor, product, version}`` candidates."""
    seen: set[tuple[str, str, str]] = set()
    out: List[dict] = []
    for s in strings:
        for vendor, product, pattern in _PATTERNS:
            m = pattern.search(s)
            if not m:
                continue
            version = m.group(1)
            key = (vendor, product, version)
            if key in seen:
                continue
            seen.add(key)
            out.append({"vendor": vendor, "product": product, "version": version})
    return out
