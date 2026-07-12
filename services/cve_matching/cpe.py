"""CPE (Common Platform Enumeration) parsing / building + family resolution.

Used by the ETL (scope the corpus to in-scope CPEs) and the matcher (exact-CPE
lookup key + family selection for tiering thresholds). Handles the CPE 2.3
formatted-string binding (`cpe:2.3:a:vendor:product:version:...`) and, as a
courtesy, the legacy 2.2 URI binding (`cpe:/a:vendor:product:version`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from . import config


@dataclass(frozen=True)
class CpeParts:
    part: str          # a | o | h  (application / os / hardware)
    vendor: str
    product: str
    version: str       # "*" when unspecified


def _unescape(field: str) -> str:
    # CPE 2.3 escapes some characters with a backslash; we only need a light touch.
    return field.replace("\\:", ":").replace("\\/", "/")


def parse_cpe(cpe: str) -> Optional[CpeParts]:
    """Parse a CPE 2.3 (or 2.2) string into its (part, vendor, product, version).

    Returns None when the string is not a recognizable CPE.
    """
    if not cpe:
        return None
    s = cpe.strip()

    # CPE 2.3 formatted string: cpe:2.3:part:vendor:product:version:...(13 fields)
    if s.lower().startswith("cpe:2.3:"):
        fields = s.split(":")
        # fields[0]='cpe', [1]='2.3', [2]=part, [3]=vendor, [4]=product, [5]=version
        if len(fields) < 6:
            return None
        return CpeParts(
            part=fields[2].lower(),
            vendor=_unescape(fields[3]).lower(),
            product=_unescape(fields[4]).lower(),
            version=_unescape(fields[5]),
        )

    # Legacy CPE 2.2 URI: cpe:/a:vendor:product:version:...
    if s.lower().startswith("cpe:/"):
        body = s[len("cpe:/"):]
        fields = body.split(":")
        # fields[0]=part, [1]=vendor, [2]=product, [3]=version
        part = fields[0].lower() if fields else ""
        vendor = fields[1].lower() if len(fields) > 1 else ""
        product = fields[2].lower() if len(fields) > 2 else ""
        version = fields[3] if len(fields) > 3 else "*"
        if not product:
            return None
        return CpeParts(part=part or "a", vendor=vendor, product=product, version=version or "*")

    return None


def build_cpe(vendor: str, product: str, version: str, part: str = "a") -> str:
    """Build a well-formed CPE 2.3 formatted string from resolved fields.

    Empty/unknown fields become the CPE ANY wildcard `*`. This is the canonical
    key used for the deterministic exact-CPE lookup against the corpus.
    """
    def field(v: str) -> str:
        v = (v or "").strip().lower()
        return v if v else "*"

    return (
        f"cpe:2.3:{part or 'a'}:{field(vendor)}:{field(product)}:{field(version)}"
        ":*:*:*:*:*:*:*"
    )


def family_for_cpe(cpe: str) -> Optional[str]:
    """Resolve the component family of a CPE string, or None if out of scope."""
    parts = parse_cpe(cpe)
    if parts is None:
        return None
    return config.family_for(parts.vendor, parts.product)


def in_scope_cpes(cpes: List[str]) -> List[str]:
    """Filter a list of CPE strings down to those in a scoped family (deduped)."""
    seen: dict[str, None] = {}
    for cpe in cpes:
        if family_for_cpe(cpe) is not None:
            seen.setdefault(cpe.strip(), None)
    return list(seen.keys())
