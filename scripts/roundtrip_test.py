"""Harness round-trip test (Task 3).

Two parts:
  1. Contract check — every file in `sample_payloads/` validates against its
     topic's model in `shared/contracts/` (the same check CI enforces).
  2. Live round-trip — emit a sample to Redpanda, consume it back, assert the
     consumed value equals what was emitted (byte-for-byte on the canonical dict).

The round-trip uses a unique job_id per run and an ephemeral consumer group so it
never collides with other messages on the topic.

Usage:
    python scripts/roundtrip_test.py            # contract check + live round-trip
    python scripts/roundtrip_test.py --offline  # contract check only (no broker)
"""
from __future__ import annotations

import json
import pathlib
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scripts.kafka_io import (  # noqa: E402
    key_for,
    make_consumer,
    make_producer,
    validate_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SAMPLES = _REPO_ROOT / "sample_payloads"


def load_sample(topic: str) -> dict:
    with open(_SAMPLES / f"{topic}.json", "r", encoding="utf-8") as fh:
        return json.load(fh)


def check_all_samples() -> list[str]:
    """Validate every sample_payloads/*.json against its contract. Returns topics."""
    topics_seen = []
    for path in sorted(_SAMPLES.glob("*.json")):
        topic = path.stem
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        validate_payload(topic, payload)  # raises on drift
        print(f"  [contract ok] {path.name}")
        topics_seen.append(topic)
    return topics_seen


def roundtrip(topic: str) -> None:
    """Emit one canonicalized sample and consume it back; assert equality."""
    payload = validate_payload(topic, load_sample(topic))
    # Unique job_id so we can pick our own message out of the topic.
    marker = str(uuid.uuid4())
    payload["job_id"] = marker
    expected_value = json.dumps(payload).encode()
    expected_key = key_for(topic, payload)

    consumer = make_consumer(f"roundtrip-{marker[:8]}", from_beginning=True)
    consumer.subscribe([topic])
    # Prime the subscription/assignment before producing.
    for _ in range(10):
        consumer.poll(0.5)

    producer = make_producer()
    producer.produce(
        topic,
        key=expected_key.encode() if expected_key else None,
        value=expected_value,
    )
    producer.flush(10)

    matched = None
    for _ in range(40):  # up to ~20s
        msg = consumer.poll(0.5)
        if msg is None or msg.error():
            continue
        value = json.loads(msg.value())
        if value.get("job_id") == marker:
            matched = (msg.key(), msg.value())
            break
    consumer.close()

    if matched is None:
        raise AssertionError(f"round-trip: no message with marker {marker} on {topic}")

    got_key, got_value = matched
    got_key = got_key.decode() if got_key else None
    assert got_key == expected_key, f"key mismatch: {got_key!r} != {expected_key!r}"
    assert json.loads(got_value) == json.loads(expected_value), "value round-trip mismatch"
    print(f"  [round-trip ok] {topic} (key={got_key})")


def main(argv: list[str]) -> int:
    offline = "--offline" in argv[1:]

    print("1) Contract check on sample_payloads/:")
    topics_seen = check_all_samples()

    if offline:
        print(f"\nOFFLINE: validated {len(topics_seen)} sample payload(s). OK.")
        return 0

    print("\n2) Live emit -> consume round-trip:")
    # A fan-out topic and a job-scoped topic exercise both keying paths.
    for topic in ("firmware.triaged", "firmware.analyzed"):
        roundtrip(topic)

    print(f"\nPASS: {len(topics_seen)} contracts valid; round-trip equality holds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
