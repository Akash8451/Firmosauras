"""Task 7 — Unpacker: four zip-bomb defenses, fan-out, counters, cleanup.

Covers the Task 7 checklist:
  * benign nested archive → N firmware.extracted + total_children == N + marker set
    + temp dir cleaned;
  * crafted zip bomb → aborted + firmware.dlq + temp cleaned;
  * zip-slip entry → rejected;
plus the other three independent defenses (symlink, recursion depth,
decompression ratio) and the backend-architecture.md rule-7 handler test.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import tarfile
import zipfile

import pytest

from shared import topics
from shared.contracts import FirmwareDlq, FirmwareExtracted
from shared.redis_keys import extraction_complete, total_children

from services.ingestion import defenses
from services.ingestion import runtime as ingestion_runtime
from services.ingestion import unpack as unpack_logic
from services.ingestion.blobstore import InMemoryBlobStore
from services.ingestion.extract import NativeExtractor

from _ingest_fakes import CapturingContext, FakeRedis

_SAMPLES = pathlib.Path(__file__).resolve().parents[3] / "sample_payloads"


# --------------------------------------------------------------------------- #
# Archive-crafting helpers.                                                    #
# --------------------------------------------------------------------------- #
def make_zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_zip_slip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zipfile.ZipInfo("../escape.bin"), b"pwned")
    return buf.getvalue()


def make_tar_with_external_symlink() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = b"benign"
        info = tarfile.TarInfo("good.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"  # absolute → escapes sandbox
        tf.addfile(link)
    return buf.getvalue()


def make_zip_bomb() -> bytes:
    # 4 MiB of zeros compresses to a few KB → ratio >> 100x.
    return make_zip({"bomb.bin": b"\x00" * (4 * 1024 * 1024)})


def make_deeply_nested_zip(levels: int) -> bytes:
    data = make_zip({"leaf.txt": b"payload"})
    for i in range(levels):
        data = make_zip({f"n{i}.zip": data})
    return data


# --------------------------------------------------------------------------- #
# Defense primitives (each layer independently).                              #
# --------------------------------------------------------------------------- #
def test_layer1_zip_slip_rejected(tmp_path):
    with pytest.raises(defenses.ZipBombError) as ei:
        defenses.safe_join(str(tmp_path), "../../etc/passwd")
    assert ei.value.layer == defenses.LAYER_ZIP_SLIP


def test_layer2_external_symlink_rejected(tmp_path):
    with pytest.raises(defenses.ZipBombError) as ei:
        defenses.check_symlink_target(str(tmp_path), "link", "/etc/passwd")
    assert ei.value.layer == defenses.LAYER_SYMLINK


def test_layer3_recursion_depth_cap():
    defenses.check_depth(defenses.RECURSION_DEPTH_CAP)  # exactly at cap = ok
    with pytest.raises(defenses.ZipBombError) as ei:
        defenses.check_depth(defenses.RECURSION_DEPTH_CAP + 1)
    assert ei.value.layer == defenses.LAYER_RECURSION_DEPTH


def test_layer4_ratio_watchdog():
    with pytest.raises(defenses.ZipBombError) as ei:
        defenses.check_ratio(output_bytes=10_001, input_bytes=100)  # 100x + 1
    assert ei.value.layer == defenses.LAYER_DECOMPRESSION_RATIO


# --------------------------------------------------------------------------- #
# Native extractor defenses on crafted archives.                              #
# --------------------------------------------------------------------------- #
def test_extractor_rejects_zip_slip(tmp_path):
    src = tmp_path / "slip.zip"
    src.write_bytes(make_zip_slip())
    with pytest.raises(defenses.ZipBombError) as ei:
        NativeExtractor().extract(str(src), str(tmp_path / "out"))
    assert ei.value.layer == defenses.LAYER_ZIP_SLIP


def test_extractor_rejects_external_symlink(tmp_path):
    src = tmp_path / "link.tar"
    src.write_bytes(make_tar_with_external_symlink())
    with pytest.raises(defenses.ZipBombError) as ei:
        NativeExtractor().extract(str(src), str(tmp_path / "out"))
    assert ei.value.layer == defenses.LAYER_SYMLINK


def test_extractor_rejects_zip_bomb(tmp_path):
    src = tmp_path / "bomb.zip"
    src.write_bytes(make_zip_bomb())
    with pytest.raises(defenses.ZipBombError) as ei:
        NativeExtractor().extract(str(src), str(tmp_path / "out"))
    assert ei.value.layer == defenses.LAYER_DECOMPRESSION_RATIO


# --------------------------------------------------------------------------- #
# Orchestration: fan-out, recursion cap, cumulative ratio, cleanup.            #
# --------------------------------------------------------------------------- #
def _blobstore_with(job_id: str, blob: bytes) -> InMemoryBlobStore:
    store = InMemoryBlobStore()
    store.put_bytes(f"raw-uploads/{job_id}/original.bin", blob)
    return store


def test_benign_nested_archive_fans_out_and_cleans_up(tmp_path):
    job_id = "job-benign"
    nested = make_zip({"c.txt": b"ccc", "d.txt": b"ddd"})
    original = make_zip({"a.txt": b"aaa", "b.txt": b"bbb", "inner.zip": nested})
    store = _blobstore_with(job_id, original)

    workroot = tmp_path / "work"
    payload = {"job_id": job_id, "sha256": "0" * 64, "is_duplicate": False, "size_bytes": len(original)}

    collected = []
    with unpack_logic.extract_job(
        payload, blobstore=store, extractor=NativeExtractor(), workdir_root=str(workroot)
    ) as subs:
        for sb in subs:
            collected.append(sb.extracted_payload(job_id))

    # 4 leaves (a.txt, b.txt, c.txt, d.txt).
    assert len(collected) == 4
    for p in collected:
        FirmwareExtracted.model_validate(p)
        assert p["job_id"] == job_id

    # Temp dir cleaned up on success (no unpack-* dirs remain).
    assert not any(str(c).startswith("unpack-") for c in os.listdir(workroot))


def test_recursion_depth_tripped(tmp_path):
    job_id = "job-deep"
    original = make_deeply_nested_zip(12)  # well past the 8-level cap
    store = _blobstore_with(job_id, original)
    payload = {"job_id": job_id, "sha256": "0" * 64, "is_duplicate": False, "size_bytes": len(original)}

    with pytest.raises(defenses.ZipBombError) as ei:
        with unpack_logic.extract_job(
            payload, blobstore=store, extractor=NativeExtractor(), workdir_root=str(tmp_path)
        ) as subs:
            list(subs)
    assert ei.value.layer == defenses.LAYER_RECURSION_DEPTH
    # Temp cleaned even on the failure path.
    assert not any(name.startswith("unpack-") for name in os.listdir(tmp_path))


# --------------------------------------------------------------------------- #
# Handler wiring (rule 7) — success and bomb-to-DLQ.                            #
# --------------------------------------------------------------------------- #
def _load_triaged() -> dict:
    with open(_SAMPLES / "firmware.triaged.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def _run_handler(payload, store, redis):
    ingestion_runtime.set_blobstore(store)
    ingestion_runtime.set_extractor(NativeExtractor())
    try:
        from services.router.handlers.unpack import handle_unpack

        ctx = CapturingContext(redis, source_topic=topics.FIRMWARE_TRIAGED, message_key=payload["job_id"])
        handle_unpack(payload, ctx)
        return ctx
    finally:
        ingestion_runtime.reset()


def test_handler_fans_out_counts_and_sets_marker():
    payload = _load_triaged()
    job_id = payload["job_id"]
    nested = make_zip({"c.txt": b"ccc", "d.txt": b"ddd"})
    original = make_zip({"a.txt": b"aaa", "inner.zip": nested})
    store = _blobstore_with(job_id, original)
    redis = FakeRedis()

    ctx = _run_handler(payload, store, redis)

    extracted = [e for e in ctx.emitted if e[0] == topics.FIRMWARE_EXTRACTED]
    assert len(extracted) == 3  # a.txt, c.txt, d.txt
    for topic, p in extracted:
        FirmwareExtracted.model_validate(p)
        # each child uploaded to its extracted/ key
        assert store.exists(p["s3_key"])

    # total_children counter matches the fan-out; marker set AFTER discovery.
    assert redis.get(total_children(job_id)) == "3"
    assert redis.get(extraction_complete(job_id)) == "1"
    # No DLQ on the happy path.
    assert not any(e[0] == topics.FIRMWARE_DLQ for e in ctx.emitted)


def test_handler_zip_bomb_routes_to_dlq_without_marker():
    payload = _load_triaged()
    job_id = payload["job_id"]
    store = _blobstore_with(job_id, make_zip_bomb())
    redis = FakeRedis()

    ctx = _run_handler(payload, store, redis)

    dlqs = [e for e in ctx.emitted if e[0] == topics.FIRMWARE_DLQ]
    assert len(dlqs) == 1
    FirmwareDlq.model_validate(dlqs[0][1])
    assert dlqs[0][1]["error"].startswith(defenses.LAYER_DECOMPRESSION_RATIO)
    # A bombed job never sets the completion marker (aggregator must not fire).
    assert redis.get(extraction_complete(job_id)) is None
