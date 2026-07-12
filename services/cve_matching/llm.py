"""Optional LLM narration — grounded triage rationale + executive summary.

This is the OPTIONAL external enhancement of SCHEMA.md §8, deliberately kept
OFF the air-gapped matching core:

  * It runs strictly DOWNSTREAM of the deterministic match decision — it explains
    or ranks, it never invents a finding (analysis-modules-rbac.md AI principle).
  * It is called ONLY for POSSIBLE / LOW_CONFIDENCE tiers — never CONFIRMED,
    never NO_MATCH.
  * On ANY failure (unconfigured, network error, bad response) it returns None
    and matching completes without narration — graceful degradation.

The provider is OpenAI-compatible (Groq default, Gemini failover); swapping is
config-only via LLM_PROVIDER / LLM_MODEL / LLM_BASE_URL / LLM_API_KEY. Keys live
only in `.env` — never hardcoded or committed.
"""
from __future__ import annotations

import logging
import os
from typing import List, Optional, Protocol

log = logging.getLogger("cve_matching.llm")


class LlmNarrator(Protocol):
    def triage_rationale(
        self, *, component: str, cve_id: str, description: str, tier: str, score: float
    ) -> Optional[str]: ...

    def executive_summary(self, *, job_id: str, findings: List[dict]) -> Optional[str]: ...

    def rag_answer(self, *, question: str, context_chunks: List[str]) -> Optional[str]: ...


class OpenAICompatibleNarrator:
    """Narrator backed by any OpenAI-compatible chat-completions endpoint.

    Lazily constructs the client so importing this module never requires `openai`.
    Every call is wrapped so a failure degrades to None rather than raising.
    """

    def __init__(
        self,
        *,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 20.0,
    ) -> None:
        self.model = model or os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
        self.base_url = base_url or os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
        self.api_key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
        self.timeout = timeout
        self._client = None  # lazy

    def is_configured(self) -> bool:
        """The LLM layer is only active when an API key is present."""
        return bool(self.api_key)

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI  # lazy

            self._client = OpenAI(
                base_url=self.base_url, api_key=self.api_key, timeout=self.timeout
            )
        return self._client

    def _chat(self, system: str, user: str, *, max_tokens: int = 220) -> Optional[str]:
        if not self.is_configured():
            return None
        try:
            client = self._get_client()
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0.2,
                max_tokens=max_tokens,
            )
            text = (resp.choices[0].message.content or "").strip()
            return text or None
        except Exception:  # graceful degradation — NEVER propagate (SCHEMA.md §8)
            log.warning("LLM call failed; continuing without narration", exc_info=True)
            return None

    def triage_rationale(
        self, *, component: str, cve_id: str, description: str, tier: str, score: float
    ) -> Optional[str]:
        system = (
            "You are a firmware security analyst. Explain, in 1-2 sentences, why an "
            "extracted component MIGHT be affected by a CVE. You are given a match that "
            "is already tiered as uncertain; do NOT assert certainty and do NOT invent "
            "details beyond the description. Frame it as guidance for analyst review."
        )
        user = (
            f"Extracted component: {component}\n"
            f"Candidate {cve_id} (tier={tier}, similarity={score:.2f}):\n{description}"
        )
        return self._chat(system, user)

    def executive_summary(self, *, job_id: str, findings: List[dict]) -> Optional[str]:
        if not findings:
            return None
        system = (
            "You are a firmware security analyst writing a brief executive summary of a "
            "vulnerability report. Summarize the overall risk in 2-4 sentences, grounded "
            "ONLY in the provided findings. Do not invent CVEs or severities."
        )
        # Compact the findings so we never ship raw firmware, only match metadata.
        lines = [
            f"- {f.get('cve_id')} [{f.get('confidence_tier')}] on {f.get('component', '?')}"
            for f in findings[:50]
        ]
        user = f"Job {job_id} findings:\n" + "\n".join(lines)
        return self._chat(system, user, max_tokens=300)

    def rag_answer(self, *, question: str, context_chunks: List[str]) -> Optional[str]:
        """Answer a question grounded ONLY in the retrieved context (RAG chat)."""
        if not context_chunks:
            return None
        system = (
            "You are a firmware security assistant. Answer the question using ONLY the "
            "provided context (CVE descriptions and this job's findings). If the answer "
            "is not in the context, say you don't have enough information. Do not invent "
            "CVEs, versions, or severities."
        )
        context = "\n".join(f"- {c}" for c in context_chunks[:20])
        user = f"Question: {question}\n\nContext:\n{context}"
        return self._chat(system, user, max_tokens=400)


# --------------------------------------------------------------------------- #
# Process default narrator (constructed lazily; overridable in tests).         #
# --------------------------------------------------------------------------- #
_default_narrator: Optional[LlmNarrator] = None
_narrator_set = False


def get_narrator() -> Optional[LlmNarrator]:
    """Return the configured narrator, or None when the LLM layer is disabled.

    When no API key is set the whole layer is off and matching runs air-gapped —
    callers treat a None narrator exactly like a failed call (no narration).
    """
    global _default_narrator, _narrator_set
    if _narrator_set:
        return _default_narrator
    narrator = OpenAICompatibleNarrator()
    _default_narrator = narrator if narrator.is_configured() else None
    _narrator_set = True
    return _default_narrator


def set_narrator(narrator: Optional[LlmNarrator]) -> None:
    """Override the process narrator (tests inject a fake or None)."""
    global _default_narrator, _narrator_set
    _default_narrator = narrator
    _narrator_set = True
