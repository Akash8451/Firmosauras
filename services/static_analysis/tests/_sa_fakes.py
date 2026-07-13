"""Minimal test doubles for the static-analysis handler test.

Named ``_sa_fakes`` to avoid a ``sys.path`` basename collision with the other
groups' ``_fakes`` / ``_ingest_fakes`` under pytest's prepend import mode.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from shared.contracts import validate_payload

from services.router.context import HandlerContext


class FakeRedis:
    def __init__(self) -> None:
        self._store: Dict[str, str] = {}

    def incr(self, key, amount=1):
        current = int(self._store.get(key, "0")) + amount
        self._store[key] = str(current)
        return current

    def get(self, key):
        return self._store.get(key)

    def set(self, key, value, **kwargs):
        self._store[key] = str(value)
        return True


class CapturingContext(HandlerContext):
    def __init__(self, redis, source_topic: str, message_key: Optional[str] = None):
        self.emitted: List[Tuple[str, dict]] = []

        def _emit(topic: str, payload: dict) -> None:
            validated = validate_payload(topic, payload)
            self.emitted.append((topic, validated))

        super().__init__(
            emit=_emit, redis=redis, source_topic=source_topic, message_key=message_key
        )
