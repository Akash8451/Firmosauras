"""MinIO artifact store — SBOM fragments, final SBOM, and report JSON.

Shared by the CVE-match handler (writes a per-sub-blob SBOM fragment) and the
aggregator (reads the fragments, writes the final `reports/{job_id}/sbom.json`
and `reports/{job_id}/report.json`). The `firmware.matched` contract has no place
to carry the resolved `(vendor, product, version)` tuples (it only carries CVE
matches), so the matcher persists them here as fragments and the aggregator
merges them at completion — that is why BOTH stages touch the SBOM (Task 10 +
Task 11).

Uses the INTERNAL MinIO client (`minio:9000`) — this is server-side object I/O,
not a presigned URL for the host, so it does NOT use MINIO_SERVER_URL /
localhost:9000 (that split is the gateway's concern). Object keys embed the
`reports/{job_id}/...` convention that ends up in `firmware.completed`.

`InMemoryArtifactStore` mirrors the interface for offline tests.
"""
from __future__ import annotations

import io
import json
import logging
import os
from typing import Dict, List, Optional, Protocol, Tuple

log = logging.getLogger("cve_matching.artifacts")


# --- key conventions -------------------------------------------------------- #
def sbom_fragment_key(job_id: str, sub_blob_id: str) -> str:
    """Per-sub-blob SBOM fragment written by the CVE-match stage."""
    return f"sbom-fragments/{job_id}/{sub_blob_id}.json"


def sbom_fragment_prefix(job_id: str) -> str:
    return f"sbom-fragments/{job_id}/"


def sbom_key(job_id: str) -> str:
    """Final assembled SBOM (matches `firmware.completed.sbom_s3_key`)."""
    return f"reports/{job_id}/sbom.json"


def report_key(job_id: str) -> str:
    """Final assembled report (matches `firmware.completed.report_s3_key`)."""
    return f"reports/{job_id}/report.json"


class ArtifactStore(Protocol):
    def put_json(self, key: str, obj: dict) -> None: ...

    def get_json(self, key: str) -> Optional[dict]: ...

    def list_json(self, prefix: str) -> List[Tuple[str, dict]]: ...


# --------------------------------------------------------------------------- #
# In-memory fake (tests).                                                      #
# --------------------------------------------------------------------------- #
class InMemoryArtifactStore:
    def __init__(self) -> None:
        self._objects: Dict[str, dict] = {}

    def put_json(self, key: str, obj: dict) -> None:
        self._objects[key] = json.loads(json.dumps(obj))  # deep copy via round-trip

    def get_json(self, key: str) -> Optional[dict]:
        obj = self._objects.get(key)
        return json.loads(json.dumps(obj)) if obj is not None else None

    def list_json(self, prefix: str) -> List[Tuple[str, dict]]:
        return [
            (k, json.loads(json.dumps(v)))
            for k, v in sorted(self._objects.items())
            if k.startswith(prefix)
        ]


# --------------------------------------------------------------------------- #
# Real MinIO-backed store.                                                     #
# --------------------------------------------------------------------------- #
class MinioArtifactStore:
    """MinIO implementation using the internal endpoint (server-side ops)."""

    def __init__(
        self,
        *,
        endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        bucket: Optional[str] = None,
        secure: Optional[bool] = None,
    ) -> None:
        # Internal ops client talks to minio:9000 (NOT the presign/localhost one).
        self.endpoint = endpoint or os.getenv("MINIO_ENDPOINT_INTERNAL", "minio:9000")
        self.access_key = access_key or os.getenv("MINIO_ROOT_USER", "minioadmin")
        self.secret_key = secret_key or os.getenv("MINIO_ROOT_PASSWORD", "minioadmin")
        self.bucket = bucket or os.getenv("MINIO_ARTIFACTS_BUCKET", "artifacts")
        if secure is None:
            secure = os.getenv("MINIO_USE_SSL", "false").lower() == "true"
        self.secure = secure
        self._client = None  # lazy

    def _get_client(self):
        if self._client is None:
            from minio import Minio  # lazy

            self._client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure,
            )
            if not self._client.bucket_exists(self.bucket):
                self._client.make_bucket(self.bucket)
        return self._client

    def put_json(self, key: str, obj: dict) -> None:
        client = self._get_client()
        data = json.dumps(obj).encode("utf-8")
        client.put_object(
            self.bucket,
            key,
            io.BytesIO(data),
            length=len(data),
            content_type="application/json",
        )

    def get_json(self, key: str) -> Optional[dict]:
        client = self._get_client()
        try:
            resp = client.get_object(self.bucket, key)
            try:
                return json.loads(resp.read().decode("utf-8"))
            finally:
                resp.close()
                resp.release_conn()
        except Exception:
            return None

    def list_json(self, prefix: str) -> List[Tuple[str, dict]]:
        client = self._get_client()
        out: List[Tuple[str, dict]] = []
        for obj in client.list_objects(self.bucket, prefix=prefix, recursive=True):
            got = self.get_json(obj.object_name)
            if got is not None:
                out.append((obj.object_name, got))
        return out
