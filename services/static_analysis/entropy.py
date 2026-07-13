"""Per-section Shannon entropy (Task 8).

Splits a blob into fixed-size sections and computes the Shannon entropy
(bits/byte, 0.0–8.0) of each. High-entropy sections are FLAGGED as likely
packed/encrypted — a cheap, deterministic signal that a region resists static
analysis (compressed payloads, ciphertext, embedded keys).

The number of sections is capped so a large blob can't produce an unbounded
``entropy_sections`` array in the ``firmware.analyzed`` event.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import List

SECTION_SIZE = 64 * 1024          # 64 KiB per section
PACKED_THRESHOLD = 7.2            # bits/byte at/above which a section looks packed
MAX_SECTIONS = 4096              # bound the emitted array size


def shannon_entropy(chunk: bytes) -> float:
    """Shannon entropy of ``chunk`` in bits per byte (0.0 – 8.0)."""
    if not chunk:
        return 0.0
    n = len(chunk)
    counts = Counter(chunk)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def section_entropies(
    data: bytes,
    *,
    section_size: int = SECTION_SIZE,
    threshold: float = PACKED_THRESHOLD,
    max_sections: int = MAX_SECTIONS,
) -> List[dict]:
    """Return ``[{offset, entropy, flagged_packed}, ...]`` (matches SCHEMA.md §2)."""
    sections: List[dict] = []
    for i in range(0, len(data), section_size):
        if len(sections) >= max_sections:
            break
        chunk = data[i : i + section_size]
        h = shannon_entropy(chunk)
        sections.append(
            {
                "offset": i,
                "entropy": round(min(h, 8.0), 4),
                "flagged_packed": h >= threshold,
            }
        )
    return sections
