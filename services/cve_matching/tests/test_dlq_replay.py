"""Task 11 — DLQ replay: retry under Redlock, backoff, and blocked second claimant."""
from __future__ import annotations

import json

from shared import topics
from shared.redis_keys import dlq_lock_key

from services.cve_matching.dlq_replay import BLOCKED, EXHAUSTED, RETRIED, SKIPPED, DlqReplayer

from _fakes import FakeRedis


def _dlq_record(job_id="jobX", original_topic=topics.FIRMWARE_ANALYZED):
    payload = json.dumps({"job_id": job_id, "sub_blob_id": "b1"})
    return {
        "original_topic": original_topic,
        "payload": payload,
        "error": "TransientError: db down",
        "failed_at": "2026-07-12T00:00:00Z",
    }


def test_replay_reinjects_to_original_topic_under_lock():
    redis = FakeRedis()
    emitted = []
    replayer = DlqReplayer(redis=redis, emit=lambda t, v: emitted.append((t, v)))

    result = replayer.replay_record(_dlq_record())
    assert result == RETRIED
    assert len(emitted) == 1
    topic, raw = emitted[0]
    assert topic == topics.FIRMWARE_ANALYZED
    assert json.loads(raw)["job_id"] == "jobX"
    # Lock released after a successful replay (available for the next retry).
    assert redis.get(dlq_lock_key("jobX")) is None


def test_second_claimant_is_blocked():
    redis = FakeRedis()
    # Simulate another instance already holding the retry lock for this job.
    redis.set(dlq_lock_key("jobX"), "other-instance-token", nx=True, px=30_000)

    emitted = []
    replayer = DlqReplayer(redis=redis, emit=lambda t, v: emitted.append((t, v)))
    result = replayer.replay_record(_dlq_record())

    assert result == BLOCKED
    assert emitted == []  # blocked claimant did not re-inject
    # The other instance's lock is untouched (token-safe release).
    assert redis.get(dlq_lock_key("jobX")) == "other-instance-token"


def test_exponential_backoff_then_exhausted():
    redis = FakeRedis()
    slept = []

    def failing_emit(topic, value):
        raise RuntimeError("broker unavailable")

    replayer = DlqReplayer(
        redis=redis,
        emit=failing_emit,
        sleep=slept.append,
        max_attempts=4,
        base_delay=0.5,
    )
    result = replayer.replay_record(_dlq_record())

    assert result == EXHAUSTED
    # 4 attempts => 3 backoff sleeps, doubling each time.
    assert slept == [0.5, 1.0, 2.0]
    # Lock released even after exhaustion.
    assert redis.get(dlq_lock_key("jobX")) is None


def test_skips_dlq_targeting_itself():
    redis = FakeRedis()
    emitted = []
    replayer = DlqReplayer(redis=redis, emit=lambda t, v: emitted.append((t, v)))
    result = replayer.replay_record(_dlq_record(original_topic=topics.FIRMWARE_DLQ))
    assert result == SKIPPED
    assert emitted == []
