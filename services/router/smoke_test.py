"""Router smoke test (Task 4) — requires a running router + live stack.

Asserts the two behaviors from the task:
  1. A valid firmware.uploaded event is dispatched through the whole stub chain
     and reaches firmware.completed (proves handler dispatch + manual commits +
     ctx.emit across all five stages).
  2. A MALFORMED message lands on firmware.dlq, AND a valid message produced
     immediately AFTER it on the SAME partition still completes — proving the
     poison pill did not stall the partition.

Run the router first (fresh group so it reads from the beginning), e.g.:
    $env:SERVICES="all"; $env:ROUTER_GROUP_ID="smoke-<run>"
    python -m services.router.runner

Then:
    python services/router/smoke_test.py
"""
from __future__ import annotations

import json
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from confluent_kafka import Consumer, Producer  # noqa: E402

from scripts.kafka_io import broker  # noqa: E402
from shared import topics  # noqa: E402

UPLOADED = topics.FIRMWARE_UPLOADED
COMPLETED = topics.FIRMWARE_COMPLETED
DLQ = topics.FIRMWARE_DLQ


def valid_uploaded(job_id: str) -> dict:
    return {
        "job_id": job_id,
        "s3_key": f"raw-uploads/{job_id}/original.bin",
        "uploaded_by": "smoke-test",
        "uploaded_at": "2026-07-12T12:00:00Z",
    }


def make_producer() -> Producer:
    return Producer({"bootstrap.servers": broker(), "enable.idempotence": True})


def produce_raw(producer: Producer, topic: str, key: str, value: bytes, partition: int) -> None:
    producer.produce(topic, key=key.encode(), value=value, partition=partition)
    producer.flush(10)


def wait_for(topic: str, predicate, timeout: float = 45.0) -> "dict | None":
    """Consume `topic` from the beginning until `predicate(value_dict)` is True."""
    consumer = Consumer(
        {
            "bootstrap.servers": broker(),
            "group.id": f"smoke-check-{uuid.uuid4().hex[:8]}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([topic])
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            msg = consumer.poll(1.0)
            if msg is None or msg.error():
                continue
            try:
                value = json.loads(msg.value())
            except ValueError:
                continue
            if predicate(value):
                return value
    finally:
        consumer.close()
    return None


def main() -> int:
    run = uuid.uuid4().hex[:8]
    job_a = f"smoke-A-{run}"       # valid, before the poison
    poison_marker = f"smoke-POISON-{run}"
    job_b = f"smoke-B-{run}"       # valid, AFTER the poison, same partition

    producer = make_producer()

    # All three to partition 0 with distinct keys: same partition (so the poison
    # sits between the two valid messages), distinct idempotency keys.
    print(f"producing A={job_a}, poison, B={job_b} to {UPLOADED} p0")
    produce_raw(producer, UPLOADED, job_a, json.dumps(valid_uploaded(job_a)).encode(), 0)
    # Malformed: valid JSON but violates the contract (missing fields + extra key).
    produce_raw(producer, UPLOADED, poison_marker,
                json.dumps({"job_id": poison_marker, "oops": True}).encode(), 0)
    produce_raw(producer, UPLOADED, job_b, json.dumps(valid_uploaded(job_b)).encode(), 0)

    failures = []

    # 1. Valid A completes the full chain.
    got_a = wait_for(COMPLETED, lambda v: v.get("job_id") == job_a)
    if got_a and got_a.get("status") == "COMPLETE":
        print(f"  PASS: {job_a} reached firmware.completed")
    else:
        failures.append(f"{job_a} did not reach firmware.completed (got {got_a})")

    # 2a. Poison lands on the DLQ with the right original_topic.
    got_dlq = wait_for(
        DLQ,
        lambda v: v.get("original_topic") == UPLOADED and poison_marker in (v.get("payload") or ""),
    )
    if got_dlq:
        print(f"  PASS: poison message routed to firmware.dlq "
              f"(error={got_dlq.get('error')!r})")
    else:
        failures.append("poison message did not reach firmware.dlq")

    # 2b. Valid B (after the poison, same partition) still completes.
    got_b = wait_for(COMPLETED, lambda v: v.get("job_id") == job_b)
    if got_b and got_b.get("status") == "COMPLETE":
        print(f"  PASS: {job_b} completed AFTER the poison — partition not stalled")
    else:
        failures.append(f"{job_b} did not complete after the poison (partition stalled?)")

    if failures:
        print("\nSMOKE TEST FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("\nPASS: dispatch + commit + DLQ + partition-unblock all verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
