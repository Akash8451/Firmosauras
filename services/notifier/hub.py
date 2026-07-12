"""Fan-out hub with per-client backpressure via coalescing mailboxes.

The key requirement (Task 12): a slow WebSocket client must not block the Kafka
consumer or the other clients. The strategy is *coalescing*, which is exactly
right for progress: only the latest snapshot matters, so intermediate updates for
a slow client are dropped rather than queued.

  * `CoalescingMailbox.offer` is NON-blocking and O(1): it overwrites the stored
    latest snapshot and signals. It never awaits, so `publish` can never be held
    up by a slow consumer.
  * `CoalescingMailbox.get` awaits the next snapshot; if several `offer`s happened
    while the client was busy, it returns only the most recent one.

Memory is bounded to one snapshot per client regardless of how far behind it is.
"""
from __future__ import annotations

import asyncio
from typing import Dict, Optional, Set


class CoalescingMailbox:
    """A one-slot, latest-wins async mailbox. Bounded memory, never blocks producers."""

    def __init__(self) -> None:
        self._latest: Optional[dict] = None
        self._has_value = False
        self._event = asyncio.Event()
        self.dropped = 0  # count of snapshots superseded before being read (observability)

    def offer(self, message: dict) -> None:
        """Non-blocking put. Coalesces: a pending unread snapshot is replaced."""
        if self._has_value:
            self.dropped += 1
        self._latest = message
        self._has_value = True
        self._event.set()

    async def get(self) -> dict:
        """Await and return the latest snapshot (coalesced)."""
        await self._event.wait()
        self._event.clear()
        self._has_value = False
        return self._latest  # type: ignore[return-value]

    def peek(self) -> Optional[dict]:
        return self._latest if self._has_value else None


class ProgressHub:
    """Routes per-job snapshots to all mailboxes subscribed to that job_id."""

    def __init__(self) -> None:
        self._subs: Dict[str, Set[CoalescingMailbox]] = {}
        self._last: Dict[str, dict] = {}

    def subscribe(self, job_id: str) -> CoalescingMailbox:
        mb = CoalescingMailbox()
        self._subs.setdefault(job_id, set()).add(mb)
        # Deliver the most recent known snapshot immediately, so a client that
        # connects mid-job isn't blank until the next event.
        last = self._last.get(job_id)
        if last is not None:
            mb.offer(last)
        return mb

    def unsubscribe(self, job_id: str, mailbox: CoalescingMailbox) -> None:
        subs = self._subs.get(job_id)
        if subs:
            subs.discard(mailbox)
            if not subs:
                self._subs.pop(job_id, None)

    def publish(self, job_id: str, message: dict) -> int:
        """Offer a snapshot to every subscriber of `job_id`. Non-blocking.

        Returns the number of clients notified. Never awaits — a slow client's
        mailbox simply coalesces.
        """
        self._last[job_id] = message
        subs = self._subs.get(job_id)
        if not subs:
            return 0
        for mb in list(subs):
            mb.offer(message)
        return len(subs)

    def subscriber_count(self, job_id: str) -> int:
        return len(self._subs.get(job_id, ()))
