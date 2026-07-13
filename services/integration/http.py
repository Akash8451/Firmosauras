"""Group-4 HTTP surface — the feedback-loop + config-management endpoints.

These are mounted onto the existing gateway app via ``include_router`` (see
``integration.app``); this module NEVER edits the Group 2/3 gateway files. Auth
reuses the SAME shared mechanism (``services.cve_matching.security`` — HS256 +
role claim); it is not a second scheme.

Endpoints (consumed by the Task 13 frontend):
  * ``POST /jobs/{job_id}/feedback`` (perm ``feedback``) — the Task 14 analyst
    verdict endpoint. Writes to the SAME ``analyst_feedback`` store as
    ``/cve/feedback`` so the recalibration loop sees every verdict.
  * ``GET  /config/thresholds``      (perm ``manage_config``) — admin view of the
    per-family confidence thresholds.
  * ``POST /config/recalibrate``     (perm ``manage_config``) — run the feedback
    loop now and install the adjusted thresholds.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from services.cve_matching import runtime, security
from services.cve_matching.feedback import VERDICTS, Feedback

from . import feedback_loop

log = logging.getLogger("integration.http")

router = APIRouter(tags=["integration"])


# --------------------------------------------------------------------------- #
# Auth (shared HS256 + role mechanism — identical to the gateway/CVE surface). #
# --------------------------------------------------------------------------- #
async def _claims(authorization: Optional[str] = Header(default=None)) -> dict:
    if not security.auth_enabled():
        return {"sub": "dev", "role": "admin"}  # local dev with no JWT_SECRET
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
# Models.                                                                      #
# --------------------------------------------------------------------------- #
class FeedbackBody(BaseModel):
    cve_id: str
    verdict: str


class FeedbackResponse(BaseModel):
    feedback_id: Optional[str]
    status: str


class ThresholdRow(BaseModel):
    family: str
    high_confidence: float
    possible: float
    low_confidence: float
    source: str


class ThresholdsResponse(BaseModel):
    thresholds: list[ThresholdRow]


class RecalibrateResponse(BaseModel):
    updated: list[str]
    thresholds: list[ThresholdRow]


# --------------------------------------------------------------------------- #
# Endpoints.                                                                   #
# --------------------------------------------------------------------------- #
@router.post("/jobs/{job_id}/feedback", response_model=FeedbackResponse, status_code=201)
async def submit_feedback(
    job_id: str, body: FeedbackBody, claims: dict = Depends(require("feedback"))
) -> FeedbackResponse:
    if body.verdict not in VERDICTS:
        raise HTTPException(status_code=422, detail=f"verdict must be one of {list(VERDICTS)}")
    feedback = Feedback(
        job_id=job_id,
        cve_id=body.cve_id,
        verdict=body.verdict,
        submitted_by=str(claims.get("sub", "unknown")),
    )
    feedback_id = runtime.get_feedback_store().submit(feedback)
    return FeedbackResponse(feedback_id=feedback_id, status="accepted")


@router.get("/config/thresholds", response_model=ThresholdsResponse)
async def get_thresholds(claims: dict = Depends(require("manage_config"))) -> ThresholdsResponse:
    return ThresholdsResponse(thresholds=[ThresholdRow(**r) for r in feedback_loop.current_thresholds()])


@router.post("/config/recalibrate", response_model=RecalibrateResponse)
async def recalibrate(claims: dict = Depends(require("manage_config"))) -> RecalibrateResponse:
    updated = feedback_loop.recalibrate_now(install=True)
    return RecalibrateResponse(
        updated=sorted(updated.keys()),
        thresholds=[ThresholdRow(**r) for r in feedback_loop.current_thresholds()],
    )


def create_feedback_app() -> FastAPI:
    """Standalone app exposing only the Group-4 feedback/config surface (tests)."""
    app = FastAPI(title="Firmosaurus Integration Surface")
    app.include_router(router)
    return app
