"""CVE HTTP surface (Group 3): RAG chat + analyst feedback endpoints.

Mounted into the gateway app via `include_router(router)`. Group 2 owns the rest
of the gateway (upload / RBAC); this module only adds the CVE endpoints and reuses
the SAME auth mechanism (`services.cve_matching.security` — HS256 + role claim).

Endpoints:
  * POST /cve/chat     — RAG chat scoped to a job. Requires `view`. Retrieval is
                         air-gapped (local pgvector); the LLM only phrases the
                         answer and degrades gracefully (sources still returned).
  * POST /cve/feedback — submit an analyst verdict on a CVE match. Requires
                         `feedback` (admin/analyst). Persisted to `analyst_feedback`
                         for the Task 14 recalibration loop.

RBAC per SCHEMA.md §5. When `JWT_SECRET` is unset (local dev) auth is bypassed with
a permissive dev identity — flagged here so a real deployment always sets the secret.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from services.cve_matching import rag, runtime, security
from services.cve_matching.feedback import VERDICTS, Feedback

log = logging.getLogger("gateway.cve_api")

router = APIRouter(prefix="/cve", tags=["cve"])


# --------------------------------------------------------------------------- #
# Auth dependencies (reuse the shared HS256 + role mechanism).                 #
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
class ChatRequest(BaseModel):
    job_id: str
    question: str = Field(min_length=1)
    top_k: int = Field(default=5, ge=1, le=20)


class ChatResponse(BaseModel):
    job_id: str
    answer: Optional[str]
    grounded: bool
    sources: List[str]
    job_status: Optional[str] = None


class FeedbackRequest(BaseModel):
    job_id: str
    cve_id: str
    verdict: str


class FeedbackResponse(BaseModel):
    feedback_id: Optional[str]
    status: str


# --------------------------------------------------------------------------- #
# Endpoints.                                                                   #
# --------------------------------------------------------------------------- #
@router.post("/chat", response_model=ChatResponse)
async def cve_chat(req: ChatRequest, claims: dict = Depends(require("view"))) -> ChatResponse:
    ctx = rag.build_context(
        req.job_id,
        req.question,
        repo=runtime.get_repo(),
        embedder=runtime.get_embedder(),
        report_store=runtime.get_report_store(),
        top_k=req.top_k,
    )
    narrator = runtime.get_narrator()
    answer: Optional[str] = None
    if narrator is not None:
        try:
            answer = narrator.rag_answer(question=req.question, context_chunks=ctx.chunks)
        except Exception:  # graceful — return grounded sources even if the LLM fails
            log.warning("rag_answer failed for job %s", req.job_id, exc_info=True)
            answer = None
    return ChatResponse(
        job_id=req.job_id,
        answer=answer,
        grounded=bool(ctx.chunks),
        sources=ctx.sources,
        job_status=ctx.job_status,
    )


@router.post("/feedback", response_model=FeedbackResponse, status_code=201)
async def submit_feedback(
    req: FeedbackRequest, claims: dict = Depends(require("feedback"))
) -> FeedbackResponse:
    if req.verdict not in VERDICTS:
        raise HTTPException(status_code=422, detail=f"verdict must be one of {list(VERDICTS)}")
    feedback = Feedback(
        job_id=req.job_id,
        cve_id=req.cve_id,
        verdict=req.verdict,
        submitted_by=str(claims.get("sub", "unknown")),
    )
    feedback_id = runtime.get_feedback_store().submit(feedback)
    return FeedbackResponse(feedback_id=feedback_id, status="accepted")


def create_cve_app() -> FastAPI:
    """Standalone app exposing only the CVE surface (for local run / tests)."""
    app = FastAPI(title="Firmosaurus CVE API")
    app.include_router(router)
    return app
