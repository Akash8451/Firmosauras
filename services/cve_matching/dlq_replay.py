"""DLQ replay worker (Task 11) — a SEPARATE consumer, not a router handler.

`firmware.dlq` collects messages that failed a stage (bad payload, transient
downstream outage, etc). This worker consumes the DLQ with its OWN consumer group
and re-injects each record onto its `original_topic` so the pipeline can retry it,
using:

  * exponential backoff between re-injection attempts, and
  * a Redlock claim (`lock:dlq_retry:{job_id}`, SCHEMA.md §3) so two replay
    instances can't double-claim the same job's retry — the second claimant is
    blocked and moves on.

It is deliberately NOT a `SERVICES` handler and is never hosted inside the router
(handlers communicate only via Kafka; this is a maintenance consumer). `emit` and
`sleep` are injected so the retry logic is unit-testable with no broker/clock.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Callable, Optional

from shared import topics
from shared.redis_keys import dlq_lock_key

from .locks import RedisLock

log = logging.getLogger("cve_matching.dlq_replay")

# Result codes returned by replay_record.
RETRIED = "retried"      # successfully re-injected onto the original topic
BLOCKED = "blocked"      # another instance holds the retry lock for this job
EXHAUSTED = "exhausted"  # re-injection kept failing past max_attempts
SKIPPED = "skipped"      # nothing to do (e.g. DLQ record targeting the DLQ itself)

DLQ_REPLAY_GROUP = "firmosaurus-dlq-replay"


class DlqReplayer:
    def __init__(
        self,
        *,
        redis,
        emit: Callable[[str, str], None],
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 5,
        base_delay: float = 0.5,
        lock_ttl_ms: int = 30_000,
    ) -> None:
        self.redis = redis
        self.emit = emit           # (topic, raw_value_str) -> None (produce)
        self.sleep = sleep
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.lock_ttl_ms = lock_ttl_ms

    def _job_id_of(self, dlq_record: dict) -> str:
        raw = dlq_record.get("payload") or ""
        try:
            return (json.loads(raw) or {}).get("job_id") or "unknown"
        except (ValueError, TypeError):
            return "unknown"

    def replay_record(self, dlq_record: dict) -> str:
        """Replay one `firmware.dlq` record. Returns one of the result codes."""
        original_topic = dlq_record.get("original_topic")
        raw_payload = dlq_record.get("payload") or ""
        if not original_topic or original_topic == topics.FIRMWARE_DLQ:
            return SKIPPED  # never loop the DLQ back onto itself

        job_id = self._job_id_of(dlq_record)
        lock = RedisLock(self.redis, dlq_lock_key(job_id), ttl_ms=self.lock_ttl_ms)
        if not lock.acquire():
            log.info("dlq retry for job %s already claimed; skipping", job_id)
            return BLOCKED

        try:
            delay = self.base_delay
            for attempt in range(1, self.max_attempts + 1):
                try:
                    self.emit(original_topic, raw_payload)
                    log.info(
                        "replayed dlq record job=%s topic=%s attempt=%d",
                        job_id, original_topic, attempt,
                    )
                    return RETRIED
                except Exception:
                    log.warning(
                        "dlq re-injection failed job=%s topic=%s attempt=%d",
                        job_id, original_topic, attempt, exc_info=True,
                    )
                    if attempt >= self.max_attempts:
                        return EXHAUSTED
                    self.sleep(delay)
                    delay *= 2  # exponential backoff
            return EXHAUSTED
        finally:
            lock.release()

    # ---- live consumer loop (real broker) --------------------------------- #
    def run(self) -> int:  # pragma: no cover (requires a live broker)
        from confluent_kafka import Consumer, KafkaError, Producer

        broker = os.getenv("REDPANDA_BROKERS", "127.0.0.1:19092")
        consumer = Consumer(
            {
                "bootstrap.servers": broker,
                "group.id": DLQ_REPLAY_GROUP,
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
            }
        )
        producer = Producer({"bootstrap.servers": broker, "enable.idempotence": True})

        def _emit(topic: str, raw_value: str) -> None:
            producer.produce(topic, value=raw_value.encode())
            producer.flush(10)

        self.emit = _emit
        consumer.subscribe([topics.FIRMWARE_DLQ])
        log.info("dlq replay worker up: group=%s broker=%s", DLQ_REPLAY_GROUP, broker)
        try:
            while True:
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        log.error("dlq consumer error: %s", msg.error())
                    continue
                try:
                    record = json.loads(msg.value())
                    self.replay_record(record)
                except Exception:
                    log.exception("failed to process dlq record")
                finally:
                    consumer.commit(message=msg, asynchronous=False)
        finally:
            producer.flush(10)
            consumer.close()
        return 0


def _make_redis():
    import redis as redis_lib

    return redis_lib.from_url(
        os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"), decode_responses=True
    )


def main() -> int:  # pragma: no cover
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    return DlqReplayer(redis=_make_redis(), emit=lambda *_: None).run()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
