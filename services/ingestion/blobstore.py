"""Blob store — read/write firmware blobs in MinIO (INTERNAL endpoint).

The triage, unpack, and analysis handlers all need to touch the raw object bytes
(hash it, download it for extraction, upload extracted sub-blobs). That is
server-side object I/O, so it uses the INTERNAL MinIO client (``minio:9000``) — it
never presigns URLs for the host (that split is the gateway's concern,
hard-constraints.md §3).

Interface + in-memory fake mirror the Group 3 storage abstractions
(``services/cve_matching/artifacts.py``). The real backend is lazy-imported
``boto3`` so unit tests run against the fake with no AWS/MinIO deps.
"""
from __future__ import annotations

import io
import logging
import os
from typing import Dict, Iterator, Optional, Protocol

log = logging.getLogger("ingestion.blobstore")

DEFAULT_CHUNK = 1024 * 1024  # 1 MiB — stream, never slurp whole firmware into RAM


class BlobStore(Protocol):
    def read_header(self, key: str, n: int) -> bytes: ...

    def iter_chunks(self, key: str, chunk_size: int = DEFAULT_CHUNK) -> Iterator[bytes]: ...

    def get_size(self, key: str) -> int: ...

    def download_to(self, key: str, dest_path: str) -> None: ...

    def put_bytes(self, key: str, data: bytes) -> None: ...

    def exists(self, key: str) -> bool: ...


# --------------------------------------------------------------------------- #
# In-memory fake (tests).                                                      #
# --------------------------------------------------------------------------- #
class InMemoryBlobStore:
    def __init__(self) -> None:
        self._objects: Dict[str, bytes] = {}

    def put_bytes(self, key: str, data: bytes) -> None:
        self._objects[key] = bytes(data)

    def read_header(self, key: str, n: int) -> bytes:
        return self._objects[key][:n]

    def iter_chunks(self, key: str, chunk_size: int = DEFAULT_CHUNK) -> Iterator[bytes]:
        data = self._objects[key]
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    def get_size(self, key: str) -> int:
        return len(self._objects[key])

    def download_to(self, key: str, dest_path: str) -> None:
        with open(dest_path, "wb") as fh:
            fh.write(self._objects[key])

    def exists(self, key: str) -> bool:
        return key in self._objects


# --------------------------------------------------------------------------- #
# Real MinIO-backed store (boto3, internal endpoint).                          #
# --------------------------------------------------------------------------- #
class MinioBlobStore:
    def __init__(
        self,
        *,
        endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        bucket: Optional[str] = None,
        region: str = "us-east-1",
    ) -> None:
        self.endpoint = endpoint or _internal_endpoint()
        self.access_key = access_key or os.getenv("MINIO_ROOT_USER", "minioadmin")
        self.secret_key = secret_key or os.getenv("MINIO_ROOT_PASSWORD", "minioadmin")
        self.bucket = bucket or os.getenv("MINIO_RAW_BUCKET", "raw-uploads")
        self.region = region
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3  # lazy
            from botocore.client import Config as BotoConfig

            self._client = boto3.client(
                "s3",
                endpoint_url=self.endpoint,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
                config=BotoConfig(signature_version="s3v4"),
            )
        return self._client

    def read_header(self, key: str, n: int) -> bytes:
        client = self._get_client()
        resp = client.get_object(Bucket=self.bucket, Key=key, Range=f"bytes=0-{n - 1}")
        try:
            return resp["Body"].read()
        finally:
            resp["Body"].close()

    def iter_chunks(self, key: str, chunk_size: int = DEFAULT_CHUNK) -> Iterator[bytes]:
        client = self._get_client()
        resp = client.get_object(Bucket=self.bucket, Key=key)
        body = resp["Body"]
        try:
            while True:
                chunk = body.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        finally:
            body.close()

    def get_size(self, key: str) -> int:
        client = self._get_client()
        resp = client.head_object(Bucket=self.bucket, Key=key)
        return int(resp["ContentLength"])

    def download_to(self, key: str, dest_path: str) -> None:
        client = self._get_client()
        client.download_file(self.bucket, key, dest_path)

    def put_bytes(self, key: str, data: bytes) -> None:
        client = self._get_client()
        client.put_object(Bucket=self.bucket, Key=key, Body=io.BytesIO(data), ContentLength=len(data))

    def exists(self, key: str) -> bool:
        client = self._get_client()
        try:
            client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False


def _internal_endpoint() -> str:
    endpoint = os.getenv("MINIO_ENDPOINT_INTERNAL", "minio:9000")
    scheme = "https" if os.getenv("MINIO_USE_SSL", "false").lower() == "true" else "http"
    return f"{scheme}://{endpoint}"
