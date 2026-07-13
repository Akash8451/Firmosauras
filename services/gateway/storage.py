"""Object storage for uploads — presigned multipart with the DUAL-client split.

hard-constraints.md §3 requires two MinIO clients:

  * ``presign`` client (endpoint ``localhost:9000`` via ``MINIO_SERVER_URL``) —
    ONLY used to generate presigned URLs the browser uploads parts to directly.
  * ``internal`` client (endpoint ``minio:9000``) — server-side ops the backend
    performs itself: initiate/complete the multipart upload and HEAD the object
    to confirm it exists (the "S3 completion callback" gate before we ever emit
    ``firmware.uploaded``).

Both talk to the same MinIO server; only the hostname differs. The upload id and
object key created by the internal client are honoured by presigned part URLs the
presign client mints, because they address the same object on the same server.

The real backend uses ``boto3`` (an S3-compatible client that works against MinIO
and, unlike the ``minio`` SDK, has first-class presigned multipart support). It is
lazy-imported so unit tests run with the in-memory fake and need no AWS deps.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol

from . import config

log = logging.getLogger("gateway.storage")


# --------------------------------------------------------------------------- #
# Value objects.                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PresignedPart:
    """A single presigned PUT URL the browser uploads one part to."""

    part_number: int
    url: str


@dataclass(frozen=True)
class PresignedUpload:
    """Everything the client needs to run a multipart upload from the host."""

    key: str
    upload_id: str
    parts: List[PresignedPart]


@dataclass(frozen=True)
class CompletedPart:
    """A part the client finished uploading (echoed back at completion)."""

    part_number: int
    etag: str


class StorageError(Exception):
    """Raised when a storage operation fails (bad upload id, missing object...)."""


# --------------------------------------------------------------------------- #
# Interface.                                                                   #
# --------------------------------------------------------------------------- #
class StorageClient(Protocol):
    def create_multipart_upload(self, key: str, part_count: int) -> PresignedUpload: ...

    def complete_multipart_upload(
        self, key: str, upload_id: str, parts: List[CompletedPart]
    ) -> None: ...

    def object_exists(self, key: str) -> bool: ...


# --------------------------------------------------------------------------- #
# In-memory fake (tests / local dev without MinIO).                           #
# --------------------------------------------------------------------------- #
class InMemoryStorage:
    """Simulates the multipart lifecycle without a real object store.

    An object only "exists" once ``complete_multipart_upload`` has been called for
    a live upload id — this is what lets tests prove the gateway never emits
    ``firmware.uploaded`` before the completion callback.
    """

    def __init__(self, *, presign_base: Optional[str] = None) -> None:
        self._presign_base = (presign_base or "http://localhost:9000").rstrip("/")
        self._bucket = config.RAW_BUCKET
        self._pending: Dict[str, str] = {}   # upload_id -> key
        self._objects: set[str] = set()      # keys that exist

    def create_multipart_upload(self, key: str, part_count: int) -> PresignedUpload:
        if part_count < 1:
            raise StorageError("part_count must be >= 1")
        upload_id = uuid.uuid4().hex
        self._pending[upload_id] = key
        parts = [
            PresignedPart(
                part_number=n,
                url=(
                    f"{self._presign_base}/{self._bucket}/{key}"
                    f"?partNumber={n}&uploadId={upload_id}"
                ),
            )
            for n in range(1, part_count + 1)
        ]
        return PresignedUpload(key=key, upload_id=upload_id, parts=parts)

    def complete_multipart_upload(
        self, key: str, upload_id: str, parts: List[CompletedPart]
    ) -> None:
        pending_key = self._pending.get(upload_id)
        if pending_key is None:
            raise StorageError(f"unknown or already-completed upload_id {upload_id!r}")
        if pending_key != key:
            raise StorageError("upload_id does not match key")
        if not parts:
            raise StorageError("cannot complete a multipart upload with no parts")
        del self._pending[upload_id]
        self._objects.add(key)

    def object_exists(self, key: str) -> bool:
        return key in self._objects


# --------------------------------------------------------------------------- #
# Real dual-client S3/MinIO backend (boto3).                                   #
# --------------------------------------------------------------------------- #
class S3Storage:
    """boto3-backed storage with the presign vs internal client split (§3)."""

    def __init__(
        self,
        *,
        presign_endpoint: Optional[str] = None,
        internal_endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        bucket: Optional[str] = None,
        region: str = "us-east-1",
    ) -> None:
        self.presign_endpoint = presign_endpoint or config.presign_endpoint_url()
        self.internal_endpoint = internal_endpoint or config.internal_endpoint_url()
        self.access_key = access_key or config.access_key()
        self.secret_key = secret_key or config.secret_key()
        self.bucket = bucket or config.RAW_BUCKET
        self.region = region
        self._presign = None   # localhost:9000 — presigned URLs only
        self._internal = None  # minio:9000 — server-side ops only

    def _client(self, endpoint: str):
        import boto3  # lazy
        from botocore.client import Config as BotoConfig

        return boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            config=BotoConfig(signature_version="s3v4"),
        )

    def _presign_client(self):
        if self._presign is None:
            self._presign = self._client(self.presign_endpoint)
        return self._presign

    def _internal_client(self):
        if self._internal is None:
            self._internal = self._client(self.internal_endpoint)
            self._ensure_bucket(self._internal)
        return self._internal

    def _ensure_bucket(self, client) -> None:
        try:
            client.head_bucket(Bucket=self.bucket)
        except Exception:
            try:
                client.create_bucket(Bucket=self.bucket)
            except Exception:
                log.warning("could not ensure bucket %s exists", self.bucket, exc_info=True)

    def create_multipart_upload(self, key: str, part_count: int) -> PresignedUpload:
        if part_count < 1:
            raise StorageError("part_count must be >= 1")
        internal = self._internal_client()
        resp = internal.create_multipart_upload(Bucket=self.bucket, Key=key)
        upload_id = resp["UploadId"]
        # Presigned part URLs are minted by the PRESIGN client so their host is
        # localhost:9000 and the browser can reach them (§3).
        presign = self._presign_client()
        expiry = config.presign_expiry_seconds()
        parts = [
            PresignedPart(
                part_number=n,
                url=presign.generate_presigned_url(
                    "upload_part",
                    Params={
                        "Bucket": self.bucket,
                        "Key": key,
                        "UploadId": upload_id,
                        "PartNumber": n,
                    },
                    ExpiresIn=expiry,
                ),
            )
            for n in range(1, part_count + 1)
        ]
        return PresignedUpload(key=key, upload_id=upload_id, parts=parts)

    def complete_multipart_upload(
        self, key: str, upload_id: str, parts: List[CompletedPart]
    ) -> None:
        if not parts:
            raise StorageError("cannot complete a multipart upload with no parts")
        internal = self._internal_client()
        ordered = sorted(parts, key=lambda p: p.part_number)
        try:
            internal.complete_multipart_upload(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={
                    "Parts": [
                        {"ETag": p.etag, "PartNumber": p.part_number} for p in ordered
                    ]
                },
            )
        except Exception as exc:
            raise StorageError(f"complete_multipart_upload failed: {exc}") from exc

    def object_exists(self, key: str) -> bool:
        internal = self._internal_client()
        try:
            internal.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False
