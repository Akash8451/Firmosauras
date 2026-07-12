"""Task 12 — backpressure hub: fan-out, coalescing, and slow-client isolation."""
from __future__ import annotations

import asyncio

from services.notifier.hub import CoalescingMailbox, ProgressHub


def test_fanout_delivers_to_all_subscribers():
    async def scenario():
        hub = ProgressHub()
        a = hub.subscribe("job")
        b = hub.subscribe("job")
        n = hub.publish("job", {"progress": "1/3"})
        assert n == 2
        assert (await a.get())["progress"] == "1/3"
        assert (await b.get())["progress"] == "1/3"

    asyncio.run(scenario())


def test_coalescing_keeps_only_latest():
    async def scenario():
        mb = CoalescingMailbox()
        mb.offer({"progress": "1/3"})
        mb.offer({"progress": "2/3"})
        mb.offer({"progress": "3/3"})
        # Only the latest survives; two were superseded.
        assert (await mb.get())["progress"] == "3/3"
        assert mb.dropped == 2

    asyncio.run(scenario())


def test_slow_client_does_not_block_publish_or_others():
    async def scenario():
        hub = ProgressHub()
        fast = hub.subscribe("job")
        slow = hub.subscribe("job")  # never reads

        # Publish a burst. publish() is non-blocking; a slow client can't stall it.
        for i in range(1, 101):
            count = hub.publish("job", {"progress": f"{i}/100"})
            assert count == 2  # both still subscribed, publish returns immediately

        # The fast client can still retrieve the latest snapshot.
        latest = await asyncio.wait_for(fast.get(), timeout=1.0)
        assert latest["progress"] == "100/100"

        # The slow client coalesced the whole burst down to a single pending slot.
        assert slow.peek()["progress"] == "100/100"
        assert slow.dropped == 99

    asyncio.run(scenario())


def test_subscribe_delivers_last_known_snapshot_immediately():
    async def scenario():
        hub = ProgressHub()
        hub.publish("job", {"progress": "5/5", "status": "complete"})  # no subscribers yet
        late = hub.subscribe("job")
        # A client that connects after the fact still gets the latest state.
        snap = await asyncio.wait_for(late.get(), timeout=1.0)
        assert snap["progress"] == "5/5"

    asyncio.run(scenario())


def test_unsubscribe_removes_client():
    hub = ProgressHub()
    mb = hub.subscribe("job")
    assert hub.subscriber_count("job") == 1
    hub.unsubscribe("job", mb)
    assert hub.subscriber_count("job") == 0
