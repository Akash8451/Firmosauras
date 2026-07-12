"""Kafka router — the poison-pill consumer loop (Group 1-owned).

Responsibilities (per `.kiro/steering/backend-architecture.md`):
  * Subscribe to the topics selected by the `SERVICES` env var (rule 5).
  * `enable.auto.commit=False`; every message processed in a try/except; on any
    failure push to `firmware.dlq` and commit the offset regardless, so one
    malformed message never stalls the partition (rule 3).
  * Dispatch each message to the handler registered for its topic
    (decorator auto-registration — no shared handler dict; rule 5).
  * Redis check-and-set idempotency so redelivery never double-processes.
  * Graceful SIGTERM/SIGINT shutdown (rule 6; child-process reaping is added by
    the unpacker when it introduces `subprocess`).

Run:
    SERVICES=all python -m services.router.runner
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import sys

from confluent_kafka import Consumer, KafkaError, Producer

from shared import topics
from shared.contracts import validate_payload
from shared.topics import partition_key

from .context import HandlerContext
from .dlq import build_dlq_record
from .idempotency import claim_message
from .registry import get_handler, registered_topics
from .topology import resolve_subscriptions

# Importing the handlers package populates the registry via import side-effects.
from . import handlers  # noqa: F401,E402

log = logging.getLogger("router")

_shutdown = False


def _install_signal_handlers() -> None:
    def _handle(signum, _frame):
        global _shutdown
        _shutdown = True
        log.info("received signal %s; shutting down after current message", signum)

    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError, RuntimeError):
            # e.g. not on the main thread, or unsupported on this platform.
            pass


def _broker() -> str:
    return os.getenv("REDPANDA_BROKERS", "127.0.0.1:19092")


def _make_consumer(group_id: str) -> Consumer:
    return Consumer(
        {
            "bootstrap.servers": _broker(),
            "group.id": group_id,
            "enable.auto.commit": False,  # rule 3: manual commits only
            "auto.offset.reset": "earliest",
            "enable.partition.eof": False,
        }
    )


def _make_producer() -> Producer:
    return Producer(
        {
            "bootstrap.servers": _broker(),
            "client.id": "firmosaurus-router-producer",
            "enable.idempotence": True,
        }
    )


def _make_redis():
    import redis as redis_lib

    return redis_lib.from_url(
        os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"),
        decode_responses=True,
    )


def _make_emit(producer: Producer):
    """Build the `ctx.emit` callable: validate OUT, key per schema, produce."""

    def emit(topic: str, payload: dict) -> None:
        validated = validate_payload(topic, payload)  # validate OUT (rule 7)
        key = partition_key(topic, validated)
        producer.produce(
            topic,
            key=key.encode() if key else None,
            value=json.dumps(validated).encode(),
        )
        producer.poll(0)  # serve delivery callbacks without blocking

    return emit


def _message_key(msg, raw_value: bytes) -> str:
    """Stable idempotency key: the Kafka key if present, else a hash of the value."""
    if msg.key():
        return msg.key().decode(errors="replace")
    return hashlib.sha256(raw_value).hexdigest()


def process_message(msg, *, emit, redis_client) -> None:
    """Process a single Kafka message. Raises on any failure (caller DLQs)."""
    topic = msg.topic()
    raw_value = msg.value()

    payload = json.loads(raw_value)  # bad JSON -> raises -> DLQ
    payload = validate_payload(topic, payload)  # validate IN (rule 7) -> DLQ on drift

    handler = get_handler(topic)
    if handler is None:
        raise RuntimeError(f"no handler registered for topic {topic!r}")

    key = _message_key(msg, raw_value)
    if not claim_message(redis_client, topic, key):
        log.info("skip duplicate message topic=%s key=%s", topic, key)
        return

    ctx = HandlerContext(
        emit=emit, redis=redis_client, source_topic=topic, message_key=key
    )
    handler(payload, ctx)
    log.info("handled topic=%s key=%s", topic, key)


def run() -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _install_signal_handlers()

    services_env = os.getenv("SERVICES", "all")
    subscriptions = resolve_subscriptions(services_env)

    # Every subscribed topic must have a registered handler.
    missing = [t for t in subscriptions if t not in registered_topics()]
    if missing:
        log.error("no handler registered for subscribed topics: %s", missing)
        return 1

    group_id = os.getenv("ROUTER_GROUP_ID", "firmosaurus-router")
    consumer = _make_consumer(group_id)
    producer = _make_producer()
    redis_client = _make_redis()
    emit = _make_emit(producer)

    consumer.subscribe(subscriptions)
    log.info(
        "router up: services=%s topics=%s group=%s broker=%s",
        services_env, subscriptions, group_id, _broker(),
    )

    try:
        while not _shutdown:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                # EOF is not an error we care about; log the rest and move on.
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("consumer error: %s", msg.error())
                continue

            try:
                process_message(msg, emit=emit, redis_client=redis_client)
            except Exception as exc:  # poison pill -> DLQ, never crash the loop
                raw = msg.value()
                raw_str = raw.decode(errors="replace") if raw is not None else ""
                log.warning(
                    "DLQ topic=%s offset=%s error=%s",
                    msg.topic(), msg.offset(), exc,
                )
                try:
                    dlq_record = build_dlq_record(msg.topic(), raw_str, f"{type(exc).__name__}: {exc}")
                    dlq_key = partition_key(topics.FIRMWARE_DLQ, dlq_record)
                    producer.produce(
                        topics.FIRMWARE_DLQ,
                        key=dlq_key.encode() if dlq_key else None,
                        value=json.dumps(dlq_record).encode(),
                    )
                    producer.flush(10)
                except Exception:  # never let DLQ production stall the partition
                    log.exception("failed to produce DLQ record; committing anyway")
            finally:
                # Manual commit regardless of success/failure (rule 3).
                consumer.commit(message=msg, asynchronous=False)
    finally:
        log.info("closing consumer and flushing producer")
        try:
            producer.flush(10)
        finally:
            consumer.close()
    return 0


if __name__ == "__main__":
    sys.exit(run())
