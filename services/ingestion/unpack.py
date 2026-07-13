"""Unpack orchestration (Task 7) — recursion, cumulative ratio watchdog, cleanup.

Downloads the triaged blob into a JOB-NAMESPACED temp dir, recursively extracts
nested containers (depth-capped), and yields each leaf file as a ``SubBlob``. The
temp dir is ALWAYS removed in ``finally`` — success AND failure paths — so a
crashed or bombed extraction never leaks disk into the WSL2 ``ext4.vhdx``.

Layer 3 (recursion depth) and the CUMULATIVE half of layer 4 (total output across
the whole job vs the original input) live here; the per-container defenses live in
the extractors. Kafka/Redis wiring (emit, counters, marker) stays in the handler —
this module only touches the blob store and the filesystem.
"""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from typing import Iterator, Optional

from . import defenses
from .blobstore import BlobStore
from .extract import Extractor

log = logging.getLogger("ingestion.unpack")


@dataclass
class SubBlob:
    sub_blob_id: str
    path: str
    parent_blob_id: Optional[str]

    def s3_key(self, job_id: str) -> str:
        # SCHEMA.md §2 firmware.extracted key convention.
        return f"extracted/{job_id}/{self.sub_blob_id}.bin"

    def read_bytes(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def extracted_payload(self, job_id: str) -> dict:
        return {
            "job_id": job_id,
            "sub_blob_id": self.sub_blob_id,
            "s3_key": self.s3_key(job_id),
            "parent_blob_id": self.parent_blob_id,
        }


def _job_workdir(job_id: str, workdir_root: Optional[str]) -> str:
    """A job-namespaced temp dir (predictable prefix, unique suffix)."""
    root = workdir_root or tempfile.gettempdir()
    os.makedirs(root, exist_ok=True)
    return tempfile.mkdtemp(prefix=f"unpack-{job_id}-", dir=root)


@contextlib.contextmanager
def extract_job(
    payload: dict,
    *,
    blobstore: BlobStore,
    extractor: Extractor,
    workdir_root: Optional[str] = None,
):
    """Context manager yielding an iterator of ``SubBlob`` for one triaged job.

    Usage (handler)::

        with extract_job(payload, blobstore=..., extractor=...) as sub_blobs:
            for sb in sub_blobs:
                ... upload + emit + INCR total_children ...

    The temp dir is cleaned up on context exit no matter what (including if the
    iterator raises a ``ZipBombError`` mid-way).
    """
    job_id = payload["job_id"]
    src_key = payload.get("s3_key") or f"raw-uploads/{job_id}/original.bin"
    workdir = _job_workdir(job_id, workdir_root)
    original = os.path.join(workdir, "original.bin")

    try:
        blobstore.download_to(src_key, original)
        input_size = os.path.getsize(original)
        yield _walk(original, extractor, workdir, input_size)
    finally:
        # Layer-agnostic guarantee: temp dir removed on success AND failure.
        shutil.rmtree(workdir, ignore_errors=True)
        log.debug("cleaned temp dir %s for job %s", workdir, job_id)


def _walk(
    path: str,
    extractor: Extractor,
    root: str,
    input_size: int,
) -> Iterator[SubBlob]:
    """Depth-first extraction generator. Maintains a running output total for the
    cumulative decompression-ratio watchdog (layer 4)."""
    produced_total = [0]  # boxed so nested calls share it
    counter = [0]

    def _next_extract_dir() -> str:
        counter[0] += 1
        return os.path.join(root, f"_extract_{counter[0]}")

    def _recurse(cur_path: str, parent_id: Optional[str], depth: int) -> Iterator[SubBlob]:
        defenses.check_depth(depth)  # layer 3

        dest = _next_extract_dir()
        children = extractor.extract(cur_path, dest)

        if not children:
            # Leaf blob — this is a sub-blob to analyze.
            yield SubBlob(sub_blob_id=str(uuid.uuid4()), path=cur_path, parent_blob_id=parent_id)
            return

        # This node is a container; assign it an id used as its children's parent.
        container_id = str(uuid.uuid4())
        for child in children:
            produced_total[0] += os.path.getsize(child)
            defenses.check_ratio(produced_total[0], input_size)  # cumulative layer 4
            yield from _recurse(child, parent_id=container_id, depth=depth + 1)

    yield from _recurse(path, parent_id=None, depth=0)
