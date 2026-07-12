"""Dependency-free test doubles shared across Group 3 tests.

We avoid the `fakeredis` dependency (not installed) with a small in-process Redis
stand-in covering exactly the commands the handlers use: SET (with NX/EX), GET,
INCR, EXISTS, DELETE, and a couple of helpers. `decode_responses=True` semantics
are mirrored (values come back as `str`).
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from shared.contracts import validate_payload

from services.router.context import HandlerContext


class FakeRedis:
    """Minimal, single-threaded Redis fake (str values, like decode_responses)."""

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._expiry: Dict[str, float] = {}

    def _expired(self, key: str) -> bool:
        exp = self._expiry.get(key)
        if exp is not None and exp <= time.time():
            self._store.pop(key, None)
            self._expiry.pop(key, None)
            return True
        return False

    def set(self, key, value, nx=False, ex=None, px=None):
        if self._expired(key):
            pass
        if nx and key in self._store:
            return None
        self._store[key] = str(value)
        if ex is not None:
            self._expiry[key] = time.time() + ex
        elif px is not None:
            self._expiry[key] = time.time() + px / 1000.0
        else:
            self._expiry.pop(key, None)
        return True

    def get(self, key):
        if self._expired(key):
            return None
        return self._store.get(key)

    def incr(self, key, amount=1):
        if self._expired(key):
            pass
        current = int(self._store.get(key, "0"))
        current += amount
        self._store[key] = str(current)
        return current

    def incrby(self, key, amount=1):
        return self.incr(key, amount)

    def exists(self, *keys):
        return sum(1 for k in keys if not self._expired(k) and k in self._store)

    def delete(self, *keys):
        count = 0
        for k in keys:
            if k in self._store:
                self._store.pop(k, None)
                self._expiry.pop(k, None)
                count += 1
        return count

    def expire(self, key, ttl):
        if key in self._store:
            self._expiry[key] = time.time() + ttl
            return True
        return False


class CapturingContext(HandlerContext):
    """A HandlerContext whose `emit` validates (like the real router) and records."""

    def __init__(self, redis, source_topic: str, message_key: Optional[str] = None):
        self.emitted: List[Tuple[str, dict]] = []

        def _emit(topic: str, payload: dict) -> None:
            validated = validate_payload(topic, payload)  # mirror runner's validate-OUT
            self.emitted.append((topic, validated))

        super().__init__(
            emit=_emit, redis=redis, source_topic=source_topic, message_key=message_key
        )


class FakeNarrator:
    """LLM narrator stand-in: returns a canned rationale, tracks which tiers it saw."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: List[dict] = []
        self.fail = fail

    def triage_rationale(self, *, component, cve_id, description, tier, score):
        self.calls.append({"cve_id": cve_id, "tier": tier, "score": score})
        if self.fail:
            raise RuntimeError("simulated LLM outage")
        return f"[stub rationale] {cve_id} may affect {component} (tier={tier})."

    def executive_summary(self, *, job_id, findings):
        self.calls.append({"summary_for": job_id, "n": len(findings)})
        if self.fail:
            raise RuntimeError("simulated LLM outage")
        return f"[stub summary] job {job_id}: {len(findings)} finding(s)."

    def rag_answer(self, *, question, context_chunks):
        self.calls.append({"question": question, "chunks": len(context_chunks)})
        if self.fail:
            raise RuntimeError("simulated LLM outage")
        return f"[stub answer] to '{question}' from {len(context_chunks)} chunk(s)."
