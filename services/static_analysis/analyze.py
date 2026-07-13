"""Static-analysis orchestration (Task 8) — pure, no Kafka/Redis wiring.

Given a sub-blob's bytes, run the string pass ONCE and feed that single list to
both secret detection and version-candidate extraction (reuse, per
analysis-modules-rbac.md), compute per-section entropy, parse hardening flags, and
assemble the ``firmware.analyzed`` payload (SCHEMA.md §2).

The emitted ``strings_found`` list is capped so a huge blob can't blow up the
Kafka message; detection still runs over the FULL string set first.
"""
from __future__ import annotations

from . import entropy, hardening, secrets, versions
from .strings_extract import extract_strings

MAX_EMITTED_STRINGS = 5000


def analyze(job_id: str, sub_blob_id: str, data: bytes) -> dict:
    """Build the ``firmware.analyzed`` payload for one sub-blob."""
    strings = extract_strings(data)  # single extraction, reused below

    version_candidates = versions.find_version_candidates(strings)
    secrets_flagged = secrets.scan_strings(strings)
    entropy_sections = entropy.section_entropies(data)
    hardening_flags = hardening.analyze_hardening(data, strings)

    return {
        "job_id": job_id,
        "sub_blob_id": sub_blob_id,
        "strings_found": strings[:MAX_EMITTED_STRINGS],
        "entropy_sections": entropy_sections,
        "version_candidates": version_candidates,
        "secrets_flagged": secrets_flagged,
        "hardening_flags": hardening_flags,
    }
