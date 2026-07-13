"""Gateway configuration — env-driven MinIO / bucket / upload settings.

Only the gateway-specific knobs live here. Auth (HS256 JWT + RBAC) is the SHARED
mechanism in ``services.cve_matching.security`` and Postgres DSN comes from
``services.cve_matching.config.postgres_dsn`` — we do NOT introduce a second auth
scheme or a second DSN helper (analysis-modules-rbac.md: one auth mechanism across
all services).

The MinIO split (hard-constraints.md §3) is the whole point of this module:

  * PRESIGN endpoint  -> ``MINIO_SERVER_URL`` (http://localhost:9000). Presigned
    URLs must resolve from the host because the frontend runs natively, not in
    Docker. This is what the browser talks to directly.
  * INTERNAL endpoint -> ``minio:9000``. Backend-to-backend object I/O
    (create/complete multipart, HEAD to confirm the object exists). Never handed
    to the browser.
"""
from __future__ import annotations

import os

# Raw-upload bucket (24h lifecycle policy is applied in docker-compose per
# hard-constraints.md §6; the gateway only reads/writes objects here).
RAW_BUCKET = os.getenv("MINIO_RAW_BUCKET", "raw-uploads")

# Object key convention for the original upload (SCHEMA.md §2 firmware.uploaded).
S3_KEY_TEMPLATE = "raw-uploads/{job_id}/original.bin"


def raw_object_key(job_id: str) -> str:
    """The canonical object key for a job's original firmware blob."""
    return S3_KEY_TEMPLATE.format(job_id=job_id)


def presign_endpoint_url() -> str:
    """Host-reachable endpoint baked into presigned URLs (localhost:9000).

    ``MINIO_SERVER_URL`` is authoritative (hard-constraints.md §3); fall back to
    building an http URL from ``MINIO_ENDPOINT`` for local dev convenience.
    """
    url = os.getenv("MINIO_SERVER_URL")
    if url:
        return url.rstrip("/")
    endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    scheme = "https" if _use_ssl() else "http"
    return f"{scheme}://{endpoint}"


def internal_endpoint_url() -> str:
    """Backend-only endpoint for server-side ops (minio:9000)."""
    endpoint = os.getenv("MINIO_ENDPOINT_INTERNAL", "minio:9000")
    scheme = "https" if _use_ssl() else "http"
    return f"{scheme}://{endpoint}"


def access_key() -> str:
    return os.getenv("MINIO_ROOT_USER", "minioadmin")


def secret_key() -> str:
    return os.getenv("MINIO_ROOT_PASSWORD", "minioadmin")


def _use_ssl() -> bool:
    return os.getenv("MINIO_USE_SSL", "false").lower() == "true"


def presign_expiry_seconds() -> int:
    """TTL for presigned part URLs (default 1h)."""
    return int(os.getenv("MINIO_PRESIGN_EXPIRY", "3600"))
