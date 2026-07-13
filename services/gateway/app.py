"""Upload Gateway (Group 2) — presigned multipart upload + 3-tier RBAC.

Flow (SCHEMA.md §2 / IMPLEMENTATION_PLAN Task 5):

  1. ``POST /uploads``           (perm ``upload``) — create the ``jobs`` row
     (``status = UPLOADED``), initiate a multipart upload, and hand back presigned
     part URLs (host-reachable localhost:9000). NO event is emitted here.
  2. client PUTs each part directly to its presigned URL, collecting ETags.
  3. ``POST /uploads/{job_id}/complete`` (perm ``upload``) — the S3 completion
     callback. Complete the multipart upload, HEAD the object to CONFIRM it
     exists, and ONLY THEN emit ``firmware.uploaded``. Never before (Task 5).
  4. ``GET /jobs/{job_id}``      (perm ``view``) — stable job status shape.

RBAC (analysis-modules-rbac.md / SCHEMA.md §5) uses the SHARED HS256 mechanism in
``services.cve_matching.security`` — reader may only view, analyst/admin may
upload. The Group 3 CVE HTTP surface is mounted here too so a single gateway
process exposes upload + CVE endpoints in local fat mode.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from services.cve_matching import security
from shared import topics

from . import config, runtime
from .events import EventEmitter
from .jobs import JobsRepo
from .storage import CompletedPart, StorageClient, StorageError

log = logging.getLogger("gateway.app")


# --------------------------------------------------------------------------- #
# Auth dependencies (reuse the shared HS256 + role mechanism — no 2nd scheme). #
# --------------------------------------------------------------------------- #
async def _claims(authorization: Optional[str] = Header(default=None)) -> dict:
    if not security.auth_enabled():
        # Local dev with no JWT_SECRET: permissive identity. Real deployments MUST
        # set JWT_SECRET so this branch is never taken.
        return {"sub": "dev", "role": "admin"}
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    try:
        return security.verify_token(token)
    except security.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


def require(permission: str):
    async def _dep(claims: dict = Depends(_claims)) -> dict:
        try:
            security.require_permission(claims, permission)
        except security.AuthError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        return claims

    return _dep


# --------------------------------------------------------------------------- #
# Request / response models.                                                   #
# --------------------------------------------------------------------------- #
class CreateUploadRequest(BaseModel):
    filename: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    part_count: int = Field(default=1, ge=1, le=10000)


class PresignedPartOut(BaseModel):
    part_number: int
    url: str


class CreateUploadResponse(BaseModel):
    job_id: str
    s3_key: str
    upload_id: str
    parts: List[PresignedPartOut]


class CompletePartIn(BaseModel):
    part_number: int = Field(ge=1)
    etag: str = Field(min_length=1)


class CompleteUploadRequest(BaseModel):
    upload_id: str = Field(min_length=1)
    parts: List[CompletePartIn] = Field(min_length=1)


class CompleteUploadResponse(BaseModel):
    job_id: str
    status: str
    emitted: bool


class JobResponse(BaseModel):
    job_id: str
    status: str
    uploaded_by: str
    created_at: str
    completed_at: Optional[str] = None


# --------------------------------------------------------------------------- #
# Routes.                                                                      #
# --------------------------------------------------------------------------- #
def create_app() -> FastAPI:
    app = FastAPI(title="Firmosaurus Upload Gateway")

    @app.post("/uploads", response_model=CreateUploadResponse, status_code=201)
    async def create_upload(
        req: CreateUploadRequest, claims: dict = Depends(require("upload"))
    ) -> CreateUploadResponse:
        storage: StorageClient = runtime.get_storage()
        jobs: JobsRepo = runtime.get_jobs_repo()

        job_id = str(uuid.uuid4())
        key = config.raw_object_key(job_id)

        # Persist the job row FIRST (status=UPLOADED) so a crash mid-upload still
        # leaves a trackable record. No firmware.uploaded is emitted here.
        jobs.create(job_id, uploaded_by=str(claims.get("sub", "unknown")))

        try:
            presigned = storage.create_multipart_upload(key, req.part_count)
        except StorageError as exc:
            raise HTTPException(status_code=502, detail=f"storage error: {exc}")

        return CreateUploadResponse(
            job_id=job_id,
            s3_key=key,
            upload_id=presigned.upload_id,
            parts=[
                PresignedPartOut(part_number=p.part_number, url=p.url)
                for p in presigned.parts
            ],
        )

    @app.post(
        "/uploads/{job_id}/complete",
        response_model=CompleteUploadResponse,
    )
    async def complete_upload(
        job_id: str,
        req: CompleteUploadRequest,
        claims: dict = Depends(require("upload")),
    ) -> CompleteUploadResponse:
        storage: StorageClient = runtime.get_storage()
        jobs: JobsRepo = runtime.get_jobs_repo()
        emitter: EventEmitter = runtime.get_emitter()

        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"unknown job {job_id}")

        key = config.raw_object_key(job_id)
        parts = [CompletedPart(part_number=p.part_number, etag=p.etag) for p in req.parts]

        # Complete the multipart upload server-side (internal client).
        try:
            storage.complete_multipart_upload(key, req.upload_id, parts)
        except StorageError as exc:
            raise HTTPException(status_code=400, detail=f"completion failed: {exc}")

        # S3 completion callback gate: CONFIRM the object exists before emitting.
        if not storage.object_exists(key):
            raise HTTPException(
                status_code=409,
                detail="object not found after completion; not emitting firmware.uploaded",
            )

        # Only now is it safe to emit firmware.uploaded (validated OUT by emitter).
        emitter.emit(
            topics.FIRMWARE_UPLOADED,
            {
                "job_id": job_id,
                "s3_key": key,
                "uploaded_by": job.uploaded_by,
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return CompleteUploadResponse(job_id=job_id, status=job.status, emitted=True)

    @app.get("/jobs/{job_id}", response_model=JobResponse)
    async def get_job(job_id: str, claims: dict = Depends(require("view"))) -> JobResponse:
        job = runtime.get_jobs_repo().get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"unknown job {job_id}")
        return JobResponse(**job.to_public())

    # Mount the Group 3 CVE HTTP surface (RAG chat + feedback) so one gateway
    # process serves upload + CVE endpoints in local fat mode.
    try:
        from .cve_api import router as cve_router

        app.include_router(cve_router)
    except Exception:  # pragma: no cover - CVE surface optional if deps missing
        log.warning("CVE HTTP surface not mounted", exc_info=True)

    return app
