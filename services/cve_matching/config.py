"""CVE-matching configuration — families, thresholds, and env-driven settings.

Two things are deliberately centralized here so no magic literals get scattered
through the handlers (SCHEMA.md §2 explicitly forbids scattering 0.90/0.70/0.50
through the code):

  1. The component families we scope the corpus to (Task 9 must NOT embed all
     250k+ NVD CVEs — only those matching families we actually normalize).
  2. The confidence-tier thresholds, stored PER FAMILY with a global default, so
     the Task 14 feedback loop can recalibrate a single family without touching code.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# --------------------------------------------------------------------------- #
# Embedding model (LOCKED — SCHEMA.md §6 / .env.example). Model + dimension    #
# change together; pgvector fixes the column dimension at table creation.      #
# --------------------------------------------------------------------------- #
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "384"))


def postgres_dsn() -> str:
    """Runtime Postgres DSN (pgvector). Honors POSTGRES_DSN, else assembles one."""
    dsn = os.getenv("POSTGRES_DSN")
    if dsn:
        return dsn
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "firmosaurus")
    user = os.getenv("POSTGRES_USER", "firmosaurus")
    pw = os.getenv("POSTGRES_PASSWORD", "firmosaurus")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


# --------------------------------------------------------------------------- #
# Confidence-tier thresholds (SCHEMA.md §2 — LOCKED initial values).           #
#                                                                              #
#   HIGH_CONFIDENCE : similarity_score >= high_confidence (0.90)               #
#   POSSIBLE        : possible (0.70) <= score < high_confidence               #
#   LOW_CONFIDENCE  : low_confidence (0.50) <= score < possible                #
#   NO_MATCH        : score < low_confidence  (never emitted)                  #
#                                                                              #
# These are the INITIAL thresholds; the Task 14 feedback loop recalibrates     #
# them per component family, hence the per-family override map.                #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ThresholdConfig:
    high_confidence: float = 0.90
    possible: float = 0.70
    low_confidence: float = 0.50

    def __post_init__(self) -> None:
        if not (0.0 <= self.low_confidence <= self.possible <= self.high_confidence <= 1.0):
            raise ValueError(
                "thresholds must satisfy 0 <= low <= possible <= high <= 1, got "
                f"low={self.low_confidence} possible={self.possible} high={self.high_confidence}"
            )


DEFAULT_THRESHOLDS = ThresholdConfig()

# Per-family overrides. Empty by default (everything uses DEFAULT_THRESHOLDS);
# Task 14 populates/persists this. Kept as config, not code, on purpose.
FAMILY_THRESHOLDS: Dict[str, ThresholdConfig] = {}


def thresholds_for(family: Optional[str]) -> ThresholdConfig:
    """Return the tier thresholds for a family, falling back to the global default."""
    if family is not None:
        override = FAMILY_THRESHOLDS.get(family)
        if override is not None:
            return override
    return DEFAULT_THRESHOLDS


def set_family_thresholds(family: str, thresholds: ThresholdConfig) -> None:
    """Install a per-family threshold override (used by the Task 14 feedback loop)."""
    FAMILY_THRESHOLDS[family] = thresholds


# --------------------------------------------------------------------------- #
# Component families (SCOPE the corpus to these — Task 9).                     #
#                                                                              #
# Common embedded-firmware components we actually normalize version strings    #
# for. A CPE whose (vendor, product) doesn't map to one of these is skipped by #
# the ETL, keeping the pgvector index inside the memory budget.                #
# Matching is case-insensitive and tolerant of vendor spelling variants        #
# (NVD is inconsistent, e.g. dropbear appears under several vendor strings).   #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ComponentFamily:
    name: str
    vendors: Tuple[str, ...]
    products: Tuple[str, ...]


COMPONENT_FAMILIES: Tuple[ComponentFamily, ...] = (
    ComponentFamily("busybox", ("busybox",), ("busybox",)),
    ComponentFamily("openssl", ("openssl",), ("openssl",)),
    ComponentFamily("libcurl", ("haxx", "curl"), ("curl", "libcurl")),
    ComponentFamily(
        "dropbear",
        ("dropbear", "dropbear_ssh_project", "matt_johnston"),
        ("dropbear", "dropbear_ssh"),
    ),
    ComponentFamily(
        "uclibc",
        ("uclibc", "uclibc-ng_project", "erik_andersen"),
        ("uclibc", "uclibc-ng"),
    ),
    ComponentFamily("linux_kernel", ("linux",), ("linux_kernel",)),
    ComponentFamily("zlib", ("zlib", "gnu"), ("zlib",)),
    ComponentFamily("openssh", ("openbsd",), ("openssh",)),
    ComponentFamily("glibc", ("gnu",), ("glibc",)),
    ComponentFamily("wpa_supplicant", ("w1.fi",), ("wpa_supplicant", "hostapd")),
    ComponentFamily("u-boot", ("denx",), ("u-boot",)),
    ComponentFamily("lighttpd", ("lighttpd",), ("lighttpd",)),
)

# Fast product-token -> family lookup. Product is the more reliable signal than
# vendor (vendor spellings drift in NVD); we match primarily on product and use
# vendor only as a tie-break / sanity check.
_PRODUCT_INDEX: Dict[str, ComponentFamily] = {
    product.lower(): fam for fam in COMPONENT_FAMILIES for product in fam.products
}


def family_for(vendor: Optional[str], product: Optional[str]) -> Optional[str]:
    """Resolve a (vendor, product) pair to a family name, or None if out of scope."""
    if not product:
        return None
    fam = _PRODUCT_INDEX.get(product.strip().lower())
    if fam is None:
        return None
    # Vendor is advisory only: if present and clearly from a different family's
    # vendor set, still trust the product match (NVD vendor strings are noisy).
    return fam.name


def is_in_scope(vendor: Optional[str], product: Optional[str]) -> bool:
    """True if the (vendor, product) belongs to a scoped family."""
    return family_for(vendor, product) is not None
