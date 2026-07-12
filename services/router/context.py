"""Per-message handler context.

A handler receives `(payload: dict, ctx: HandlerContext)`. The context is the ONLY
way a handler talks to the outside world:

  * `ctx.emit(topic, payload)` — validate (OUT) and produce to the next topic.
  * `ctx.redis` — the shared Redis client (counters, markers, idempotency).

Handlers MUST NOT call each other in-process (backend-architecture.md rule 4);
all inter-stage communication goes through `ctx.emit`, i.e. Kafka.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class HandlerContext:
    emit: Callable[[str, dict], None]
    redis: object
    source_topic: str
    message_key: Optional[str]
