"""Dependency-free test doubles for the Group 2 ingestion tests.

Named ``_ingest_fakes`` (not ``_fakes``) so it never collides on ``sys.path`` with
``services/cve_matching/tests/_fakes.py`` when the whole suite runs under pytest's
prepend import mode.

A small in-process Redis stand-in covering the commands the ingestion handlers
use — SETBIT / GETBIT (Bloom bitmap), INCR (fan-out counters), SET (NX/EX) / GET
/ EXISTS (markers + idempotency). Bits are stored as a set of set-offsets so a
100k-insert Bloom FPR test stays fast without a real Redis.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Set, Tuple

from shared.contracts import validate_payload

from services.router.context import HandlerContext


class FakeRedis:
    """Minimal single-threaded Redis fake (str values, like decode_responses)."""

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._expiry: Dict[str, float] = {}
        self._bitmaps: Dict[str, Set[int]] = {}

    def _expired(self, key: str) -> bool:
        exp = self._expiry.get(key)
        if exp is not None and exp <= time.time():
            self._store.pop(key, None)
            self._expiry.pop(key, None)
            return True
        return False

    # --- string / counter ops --- #
    def set(self, key, value, nx=False, ex=None, px=None):
        self._expired(key)
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
        self._expired(key)
        current = int(self._store.get(key, "0")) + amount
        self._store[key] = str(current)
        return current

    def incrby(self, key, amount=1):
        return self.incr(key, amount)

    def exists(self, *keys):
        return sum(1 for k in keys if not self._expired(k) and k in self._store)

    def delete(self, *keys):
        count = 0
        for k in keys:
            if k in self._store or k in self._bitmaps:
                self._store.pop(k, None)
                self._expiry.pop(k, None)
                self._bitmaps.pop(k, None)
                count += 1
        return count

    # --- bitmap ops (Bloom filter) --- #
    def setbit(self, key, offset, value):
        bits = self._bitmaps.setdefault(key, set())
        prev = 1 if offset in bits else 0
        if value:
            bits.add(offset)
        else:
            bits.discard(offset)
        return prev

    def getbit(self, key, offset):
        return 1 if offset in self._bitmaps.get(key, set()) else 0


class CapturingContext(HandlerContext):
    """A HandlerContext whose ``emit`` validates (like the real router) and records."""

    def __init__(self, redis, source_topic: str, message_key: Optional[str] = None):
        self.emitted: List[Tuple[str, dict]] = []

        def _emit(topic: str, payload: dict) -> None:
            validated = validate_payload(topic, payload)  # mirror runner's validate-OUT
            self.emitted.append((topic, validated))

        super().__init__(
            emit=_emit, redis=redis, source_topic=source_topic, message_key=message_key
        )
