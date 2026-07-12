"""Version-candidate normalization (Task 10, step 1) + candidate CPE construction.

The static-analysis stage emits `version_candidates` that can be messy (e.g. a
vendor banner like "BusyBox v1.31.1 (2020-04-14 15:22:11 UTC)"). This module
regex-normalizes each candidate into a clean `(vendor, product, version)` tuple
using per-family patterns, resolves its component family, and constructs the
well-formed CPE 2.3 string(s) used for the deterministic exact-CPE lookup.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from . import config, cpe as cpe_mod

# Per-family version extractors. OpenSSL historically uses a letter-suffixed
# patch (e.g. 1.0.2h); most others are plain dotted numerics. The default is
# permissive (1-4 dotted components with an optional letter suffix).
_VERSION_PATTERNS: Dict[str, re.Pattern] = {
    "openssl": re.compile(r"\d+\.\d+\.\d+[a-z]?"),
    "busybox": re.compile(r"\d+\.\d+\.\d+"),
    "linux_kernel": re.compile(r"\d+\.\d+(?:\.\d+){0,2}"),
    "dropbear": re.compile(r"\d{4}\.\d+|\d+\.\d+"),  # dropbear uses e.g. 2020.81
}
_DEFAULT_VERSION_PATTERN = re.compile(r"\d+(?:\.\d+){1,3}[a-z]?")


@dataclass(frozen=True)
class NormalizedComponent:
    vendor: str
    product: str
    version: Optional[str]      # clean semantic version, or None if none found
    family: Optional[str]
    raw_text: str               # original messy text (used for embedding fallback)


def extract_version(text: str, family: Optional[str]) -> Optional[str]:
    """Pull a clean version token out of a messy string using the family pattern."""
    if not text:
        return None
    pattern = _VERSION_PATTERNS.get(family or "", _DEFAULT_VERSION_PATTERN)
    m = pattern.search(text)
    if m:
        return m.group(0)
    # Fall back to the permissive default if a family-specific pattern missed.
    m = _DEFAULT_VERSION_PATTERN.search(text)
    return m.group(0) if m else None


def normalize_candidate(vc: dict) -> NormalizedComponent:
    """Normalize one `version_candidates[]` entry into a clean component tuple."""
    vendor = (vc.get("vendor") or "").strip().lower()
    product = (vc.get("product") or "").strip().lower()
    version_raw = str(vc.get("version") or "").strip()

    family = config.family_for(vendor, product)

    # Extract a clean version from the version field, then (as a fallback) from
    # the combined banner text — messy scanners sometimes fold it into product.
    version = extract_version(version_raw, family)
    if version is None:
        version = extract_version(f"{product} {version_raw}", family)

    raw_text = " ".join(t for t in (vendor, product, version_raw) if t).strip()
    return NormalizedComponent(
        vendor=vendor,
        product=product,
        version=version,
        family=family,
        raw_text=raw_text or f"{vendor} {product}".strip(),
    )


def candidate_cpes(component: NormalizedComponent) -> List[str]:
    """Construct the exact-lookup CPE candidates for a normalized component.

    With no resolved version there is nothing to match exactly (a wildcard CPE
    would not equal a specific NVD CPE), so we return [] and let the caller fall
    back to embedding similarity. When the component maps to a known family we
    try every (vendor, product) spelling variant NVD is known to use, since the
    exact-CPE key must byte-match the stored corpus string.
    """
    if not component.version:
        return []

    combos: List[tuple[str, str]] = []
    fam = config.family_by_name(component.family)
    if fam is not None:
        for vendor in fam.vendors:
            for product in fam.products:
                combos.append((vendor, product))
    # Always also try the exact spelling the scanner reported.
    if component.vendor or component.product:
        combos.append((component.vendor, component.product))

    seen: dict[str, None] = {}
    for vendor, product in combos:
        if not product:
            continue
        seen.setdefault(cpe_mod.build_cpe(vendor, product, component.version), None)
    return list(seen.keys())
