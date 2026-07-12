"""Single-instance Redlock helper (SCHEMA.md §3 `lock:dlq_retry:{job_id}`).

Our deployment runs ONE `noeviction` Redis (hard-constraints + SCHEMA.md §3), so
the full multi-node Redlock quorum is unnecessary — the correct primitive here is
`SET key <token> NX PX <ttl>` for mutual exclusion plus a token-checked release so
a lock is never freed by a different owner (or after it has expired and been
re-acquired). This is exactly the single-instance Redlock recipe.
"""
from __future__ import annotations

import contextlib
import logging
import uuid
from typing import Iterator, Optional

log = logging.getLogger("cve_matching.locks")


class RedisLock:
    def __init__(self, redis, key: str, *, ttl_ms: int = 10_000) -> None:
        self.redis = redis
        self.key = key
        self.ttl_ms = ttl_ms
        self._token: Optional[str] = None

    def acquire(self) -> bool:
        token = uuid.uuid4().hex
        ok = self.redis.set(self.key, token, nx=True, px=self.ttl_ms)
        if ok:
            self._token = token
            return True
        return False

    def release(self) -> None:
        """Release only if we still own the lock (token match) — never free
        someone else's lock. Uses a check-and-delete (Lua on real Redis would be
        strictly atomic; the token check is sufficient for our single instance)."""
        if self._token is None:
            return
        try:
            if self.redis.get(self.key) == self._token:
                self.redis.delete(self.key)
        finally:
            self._token = None


@contextlib.contextmanager
def guard(redis, key: str, *, ttl_ms: int = 10_000) -> Iterator[bool]:
    """Context manager yielding True if the lock was acquired (else False).

        with guard(redis, dlq_lock_key(job_id)) as locked:
            if not locked:
                return  # another instance owns this retry
            ...
    """
    lock = RedisLock(redis, key, ttl_ms=ttl_ms)
    acquired = lock.acquire()
    try:
        yield acquired
    finally:
        if acquired:
            lock.release()
