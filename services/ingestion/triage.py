"""Triage orchestration (Task 6) — pure logic, no Kafka/Redis wiring.

Given a ``firmware.uploaded`` payload, a blob store, and a Bloom filter, decide
whether the blob is CLEAN (→ emit ``firmware.triaged``) or REJECTED (→ route to
``firmware.dlq`` with a reason code). Order of checks:

  1. fetch the header + stream the bytes to compute SHA-256 and the true size;
  2. magic-byte + declared-size pre-check (reject unknown / bomb-precursor);
  3. Bloom dedup — a hash already seen is a duplicate and is rejected.

The handler (``services/router/handlers/triage.py``) does the I/O; this returns a
decision object so it is trivially unit-testable with in-memory fakes.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from .bloom import BloomFilter
from .blobstore import BlobStore
from .magic import HEADER_BYTES, precheck


@dataclass(frozen=True)
class TriageResult:
    clean: bool
    sha256: str
    size_bytes: int
    is_duplicate: bool = False
    reason: Optional[str] = None  # reason code when clean is False

    def triaged_payload(self, job_id: str) -> dict:
        """The ``firmware.triaged`` payload for a clean blob."""
        return {
            "job_id": job_id,
            "sha256": self.sha256,
            "is_duplicate": self.is_duplicate,
            "size_bytes": self.size_bytes,
        }


def _hash_and_size(blobstore: BlobStore, key: str) -> tuple[str, int]:
    """Stream the object through SHA-256 without slurping it all into RAM."""
    digest = hashlib.sha256()
    size = 0
    for chunk in blobstore.iter_chunks(key):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def triage(payload: dict, *, blobstore: BlobStore, bloom: BloomFilter) -> TriageResult:
    """Run triage for one ``firmware.uploaded`` payload."""
    key = payload["s3_key"]

    header = blobstore.read_header(key, HEADER_BYTES)
    sha256, size_bytes = _hash_and_size(blobstore, key)

    # 2) magic-byte + declared-size pre-check.
    check = precheck(header, size_bytes)
    if not check.ok:
        return TriageResult(clean=False, sha256=sha256, size_bytes=size_bytes, reason=check.reason)

    # 3) Bloom dedup — a previously-seen hash is a duplicate.
    is_new = bloom.add_if_absent(sha256)
    if not is_new:
        return TriageResult(
            clean=False, sha256=sha256, size_bytes=size_bytes, is_duplicate=True, reason="duplicate"
        )

    return TriageResult(clean=True, sha256=sha256, size_bytes=size_bytes, is_duplicate=False)
