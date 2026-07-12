"""Match orchestrator (Task 10) — pure, I/O-free given its dependencies.

`match_sub_blob` runs the deterministic-first pipeline for ONE `firmware.analyzed`
event and returns both the validated `firmware.matched` payload and the resolved
SBOM components for that sub-blob. It performs NO Kafka/Redis/MinIO I/O itself —
the handler wires those around it — which keeps the matching logic fully unit
testable offline.

Pipeline (SCHEMA.md §2 conventions + analysis-modules-rbac.md AI principle):
  1. Normalize each version candidate -> (vendor, product, version) + family.
  2. Build well-formed CPE(s); exact lookup against the local corpus.
  3. Exact hit  -> CONFIRMED (matched_via=exact_cpe, similarity_score=null).
  4. No exact hit -> embed the raw string, cosine similarity search (top-k).
  5. Tier each hit from its score; DROP NO_MATCH (never emitted).
  6. LLM triage rationale ONLY for POSSIBLE / LOW_CONFIDENCE (graceful -> None).
De-duplicate by cve_id keeping the highest-ranked tier. A sub-blob with no
findings yields `cve_matches: []`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from shared import topics
from shared.contracts import ConfidenceTier, MatchedVia, Sbom, validate_payload

from . import normalize, tiering
from .corpus import CorpusRepository
from .embeddings import Embedder
from .llm import LlmNarrator

log = logging.getLogger("cve_matching.matcher")

DEFAULT_TOP_K = 5


@dataclass
class MatchOutput:
    matched_payload: dict                     # validated firmware.matched dict
    sbom_components: List[dict] = field(default_factory=list)  # SbomComponent dicts


@dataclass
class _Candidate:
    cve_id: str
    tier: ConfidenceTier
    matched_via: MatchedVia
    similarity_score: Optional[float]
    description: str
    component_text: str


def match_sub_blob(
    analyzed: dict,
    *,
    repo: CorpusRepository,
    embedder: Embedder,
    narrator: Optional[LlmNarrator] = None,
    top_k: int = DEFAULT_TOP_K,
) -> MatchOutput:
    """Match one `firmware.analyzed` payload; return the `firmware.matched` payload."""
    job_id = analyzed["job_id"]
    sub_blob_id = analyzed["sub_blob_id"]

    best: Dict[str, _Candidate] = {}
    sbom_components: List[dict] = []
    seen_components: set = set()

    for vc in analyzed.get("version_candidates", []):
        comp = normalize.normalize_candidate(vc)

        # Record the resolved component for the SBOM (deduped, needs a version).
        sbom_version = comp.version or (str(vc.get("version") or "").strip())
        if comp.product and sbom_version:
            ident = (comp.vendor, comp.product, sbom_version)
            if ident not in seen_components:
                seen_components.add(ident)
                sbom_components.append(
                    {
                        "vendor": comp.vendor,
                        "product": comp.product,
                        "version": sbom_version,
                        "source_sub_blob_id": sub_blob_id,
                    }
                )

        # Step 2-3: deterministic exact-CPE lookup.
        exact_records = []
        for cpe_string in normalize.candidate_cpes(comp):
            exact_records.extend(repo.exact_cpe_lookup(cpe_string))

        if exact_records:
            for rec in exact_records:
                _offer(
                    best,
                    _Candidate(
                        cve_id=rec.cve_id,
                        tier=ConfidenceTier.CONFIRMED,
                        matched_via=MatchedVia.EXACT_CPE,
                        similarity_score=None,
                        description=rec.description,
                        component_text=comp.raw_text,
                    ),
                )
            continue  # exact match found — no need for the fuzzy fallback

        # Step 4-5: embedding similarity fallback.
        query_vec = embedder.encode(comp.raw_text)
        for rec, score in repo.similarity_search(query_vec, top_k=top_k):
            tier = tiering.tier_for_score(score, rec.family or comp.family)
            if tier == ConfidenceTier.NO_MATCH:
                continue  # never emitted
            _offer(
                best,
                _Candidate(
                    cve_id=rec.cve_id,
                    tier=tier,
                    matched_via=MatchedVia.EMBEDDING_SIMILARITY,
                    similarity_score=round(float(score), 4),
                    description=rec.description,
                    component_text=comp.raw_text,
                ),
            )

    cve_matches = [_to_match_dict(c, narrator) for c in best.values()]
    # Stable ordering: strongest tier first, then CVE id.
    cve_matches.sort(key=lambda m: (-tiering.tier_rank(ConfidenceTier(m["confidence_tier"])), m["cve_id"]))

    payload = {"job_id": job_id, "sub_blob_id": sub_blob_id, "cve_matches": cve_matches}
    validated = validate_payload(topics.FIRMWARE_MATCHED, payload)  # validate OUT
    return MatchOutput(matched_payload=validated, sbom_components=sbom_components)


def _offer(best: Dict[str, _Candidate], cand: _Candidate) -> None:
    """Keep the highest-ranked tier per cve_id; break ties by higher score."""
    existing = best.get(cand.cve_id)
    if existing is None:
        best[cand.cve_id] = cand
        return
    new_rank = tiering.tier_rank(cand.tier)
    old_rank = tiering.tier_rank(existing.tier)
    if new_rank > old_rank:
        best[cand.cve_id] = cand
    elif new_rank == old_rank:
        if (cand.similarity_score or 0.0) > (existing.similarity_score or 0.0):
            best[cand.cve_id] = cand


def _to_match_dict(cand: _Candidate, narrator: Optional[LlmNarrator]) -> dict:
    rationale: Optional[str] = None
    if tiering.needs_llm_rationale(cand.tier):
        rationale = _safe_rationale(narrator, cand)
    return {
        "cve_id": cand.cve_id,
        "confidence_tier": cand.tier.value,
        "similarity_score": cand.similarity_score,
        "matched_via": cand.matched_via.value,
        "llm_rationale": rationale,
    }


def _safe_rationale(narrator: Optional[LlmNarrator], cand: _Candidate) -> Optional[str]:
    """Call the LLM for narration; ANY failure -> None (graceful degradation)."""
    if narrator is None:
        return None
    try:
        return narrator.triage_rationale(
            component=cand.component_text,
            cve_id=cand.cve_id,
            description=cand.description,
            tier=cand.tier.value,
            score=cand.similarity_score or 0.0,
        )
    except Exception:  # never let narration failure break matching
        log.warning("triage rationale failed for %s; continuing", cand.cve_id, exc_info=True)
        return None


def build_sbom_fragment(job_id: str, components: List[dict]) -> dict:
    """Build a validated SBOM fragment (SCHEMA.md §4) for one sub-blob's components."""
    sbom = Sbom(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc),
        components=components,  # type: ignore[arg-type]  (pydantic coerces dicts)
    )
    return sbom.model_dump(mode="json")
