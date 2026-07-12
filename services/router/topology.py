"""SERVICES env -> subscribed topics, and the stage -> next-topic pipeline map.

Mirrors the table in `.kiro/steering/backend-architecture.md` rule 5. Handler
code is identical in every mode; only the subscription set changes.
"""
from __future__ import annotations

from shared import topics

# `SERVICES` value -> the topic that stage CONSUMES (rule 5 table).
SERVICE_TO_TOPIC = {
    "triage": topics.FIRMWARE_UPLOADED,
    "unpack": topics.FIRMWARE_TRIAGED,
    "analysis": topics.FIRMWARE_EXTRACTED,
    "match": topics.FIRMWARE_ANALYZED,
    "aggregate": topics.FIRMWARE_MATCHED,
}

# Pipeline order: incoming topic -> the topic the stage produces to next.
# `firmware.matched` -> `firmware.completed` is the terminal produce (aggregator).
NEXT_TOPIC = {
    topics.FIRMWARE_UPLOADED: topics.FIRMWARE_TRIAGED,
    topics.FIRMWARE_TRIAGED: topics.FIRMWARE_EXTRACTED,
    topics.FIRMWARE_EXTRACTED: topics.FIRMWARE_ANALYZED,
    topics.FIRMWARE_ANALYZED: topics.FIRMWARE_MATCHED,
    topics.FIRMWARE_MATCHED: topics.FIRMWARE_COMPLETED,
}


def resolve_subscriptions(services_env: str) -> list[str]:
    """Turn a `SERVICES` value (e.g. "all" or "triage,unpack") into consumed topics.

    Raises ValueError on an unknown service name so a typo fails fast at startup
    rather than silently subscribing to nothing.
    """
    raw = (services_env or "").strip().lower()
    if not raw:
        raise ValueError("SERVICES is empty; expected 'all' or comma-separated stages")

    names: list[str]
    if raw == "all":
        names = list(SERVICE_TO_TOPIC.keys())
    else:
        names = [part.strip() for part in raw.split(",") if part.strip()]

    unknown = [n for n in names if n not in SERVICE_TO_TOPIC]
    if unknown:
        raise ValueError(
            f"unknown SERVICES entries {unknown}; "
            f"valid: {sorted(SERVICE_TO_TOPIC)} or 'all'"
        )

    # De-duplicate while preserving order.
    seen: dict[str, None] = {}
    for n in names:
        seen.setdefault(SERVICE_TO_TOPIC[n], None)
    return list(seen.keys())
