"""Task 6 — Triage handler + REAL Bloom filter.

Covers the Task 6 test checklist:
  (a) every inserted hash tests positive (Bloom has zero false negatives);
  (b) measured FPR on a disjoint 10k set stays ≤ 2%;
  (c) k = 7 and the 7 bit positions are distinct (not a single-bit hash set);
  (d) a duplicate hash routes to firmware.dlq;
  (e) bad magic bytes route to firmware.dlq;
plus the backend-architecture.md rule-7 handler test: a clean firmware.uploaded
sample produces an on-contract firmware.triaged.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

from shared import topics
from shared.contracts import FirmwareDlq, FirmwareTriaged, validate_payload
from shared.redis_keys import bloom_key

from services.ingestion import runtime as ingestion_runtime
from services.ingestion.bloom import BLOOM_K, BLOOM_M_BITS, BloomFilter, bit_positions
from services.ingestion.blobstore import InMemoryBlobStore

from _ingest_fakes import CapturingContext, FakeRedis

_SAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads"


def _load_uploaded() -> dict:
    with open(_SAMPLES / "firmware.uploaded.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def _elf_blob(size: int = 256) -> bytes:
    """A minimal blob with a valid ELF magic, padded to a plausible size."""
    return b"\x7fELF" + b"\x00" * (size - 4)


# --------------------------------------------------------------------------- #
# Bloom filter properties.                                                     #
# --------------------------------------------------------------------------- #
def test_k_is_7_and_positions_distinct():
    # (c) real Bloom filter: k>1 and k distinct bit positions.
    assert BLOOM_K == 7
    positions = bit_positions("some-firmware-sha256-digest")
    assert len(positions) == 7
    assert len(set(positions)) == 7  # distinct — not a lossy single-bit hash set
    assert all(0 <= p < BLOOM_M_BITS for p in positions)


def test_no_false_negatives():
    # (a) every inserted hash must subsequently test positive.
    bloom = BloomFilter(FakeRedis())
    inserted = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(5000)]
    for h in inserted:
        bloom.add(h)
    assert all(bloom.contains(h) for h in inserted)


def test_false_positive_rate_within_bound():
    # (b) target FPR ~1% at n=100k; measured on a disjoint 10k set must be ≤ 2%.
    bloom = BloomFilter(FakeRedis())
    for i in range(100_000):
        bloom.add(hashlib.sha256(f"member-{i}".encode()).hexdigest())

    trials = 10_000
    false_positives = sum(
        1
        for i in range(trials)
        if bloom.contains(hashlib.sha256(f"stranger-{i}".encode()).hexdigest())
    )
    fpr = false_positives / trials
    assert fpr <= 0.02, f"measured FPR {fpr:.4f} exceeds 2% bound"


def test_add_if_absent_dedups():
    bloom = BloomFilter(FakeRedis())
    h = hashlib.sha256(b"blob").hexdigest()
    assert bloom.add_if_absent(h) is True   # newly added
    assert bloom.add_if_absent(h) is False  # duplicate


# --------------------------------------------------------------------------- #
# Triage handler wiring (rule 7) + reject paths.                               #
# --------------------------------------------------------------------------- #
def _run_handler(payload: dict, blob: bytes, redis: FakeRedis):
    store = InMemoryBlobStore()
    store.put_bytes(payload["s3_key"], blob)
    ingestion_runtime.set_blobstore(store)
    try:
        from services.router.handlers.triage import handle_triage

        ctx = CapturingContext(redis, source_topic=topics.FIRMWARE_UPLOADED, message_key=payload["job_id"])
        handle_triage(payload, ctx)
        return ctx
    finally:
        ingestion_runtime.reset()


def test_clean_blob_emits_on_contract_triaged():
    payload = _load_uploaded()
    ctx = _run_handler(payload, _elf_blob(256), FakeRedis())

    assert len(ctx.emitted) == 1
    topic, emitted = ctx.emitted[0]
    assert topic == topics.FIRMWARE_TRIAGED
    FirmwareTriaged.model_validate(emitted)  # on-contract
    assert emitted == validate_payload(topics.FIRMWARE_TRIAGED, emitted)
    assert emitted["job_id"] == payload["job_id"]
    assert emitted["is_duplicate"] is False
    assert emitted["size_bytes"] == 256
    # sha256 is the digest of the actual blob bytes.
    assert emitted["sha256"] == hashlib.sha256(_elf_blob(256)).hexdigest()


def test_duplicate_hash_routes_to_dlq():
    # (d) a second upload of identical bytes is a duplicate → firmware.dlq.
    payload = _load_uploaded()
    redis = FakeRedis()  # shared bitmap across both runs

    ctx1 = _run_handler(payload, _elf_blob(256), redis)
    assert ctx1.emitted[0][0] == topics.FIRMWARE_TRIAGED

    ctx2 = _run_handler(payload, _elf_blob(256), redis)
    assert len(ctx2.emitted) == 1
    topic, dlq = ctx2.emitted[0]
    assert topic == topics.FIRMWARE_DLQ
    FirmwareDlq.model_validate(dlq)
    assert dlq["original_topic"] == topics.FIRMWARE_UPLOADED
    assert dlq["error"] == "duplicate"


def test_bad_magic_bytes_routes_to_dlq():
    # (e) unknown magic bytes → firmware.dlq with reason unknown_format.
    payload = _load_uploaded()
    ctx = _run_handler(payload, b"NOTAKNOWNMAGIC" + b"\x00" * 250, FakeRedis())

    assert len(ctx.emitted) == 1
    topic, dlq = ctx.emitted[0]
    assert topic == topics.FIRMWARE_DLQ
    FirmwareDlq.model_validate(dlq)
    assert dlq["error"] == "unknown_format"


def test_too_small_blob_routes_to_dlq():
    payload = _load_uploaded()
    ctx = _run_handler(payload, b"\x7fELF\x00\x00", FakeRedis())  # 6 bytes < MIN_BLOB_BYTES
    topic, dlq = ctx.emitted[0]
    assert topic == topics.FIRMWARE_DLQ
    assert dlq["error"] == "too_small"


def test_bloom_uses_the_schema_key():
    # Guard against a drifted key name — must be exactly bloom:firmware_hashes.
    redis = FakeRedis()
    BloomFilter(redis).add("x")
    assert bloom_key() == "bloom:firmware_hashes"
    assert redis._bitmaps.get("bloom:firmware_hashes")
