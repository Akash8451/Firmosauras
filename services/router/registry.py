"""Decorator-based handler registry.

Handlers self-register with `@register(topic)` where `topic` is the topic they
CONSUME. There is deliberately NO shared `TOPIC_HANDLERS` dict for groups to
merge-conflict on — the registry is populated purely by import side-effects when
`runner.py` imports the `handlers` package.

    from services.router.registry import register
    from shared import topics

    @register(topics.FIRMWARE_UPLOADED)
    def handle_triage(payload, ctx):
        ...
"""
from __future__ import annotations

from typing import Callable, Dict

# Maps consumed-topic -> handler callable `(payload: dict, ctx) -> None`.
_REGISTRY: Dict[str, Callable] = {}


def register(topic: str) -> Callable[[Callable], Callable]:
    """Register the decorated function as the handler for `topic`."""

    def decorator(fn: Callable) -> Callable:
        if topic in _REGISTRY and _REGISTRY[topic] is not fn:
            raise RuntimeError(
                f"duplicate handler registration for topic {topic!r}: "
                f"{_REGISTRY[topic].__name__} vs {fn.__name__}"
            )
        _REGISTRY[topic] = fn
        return fn

    return decorator


def get_handler(topic: str) -> "Callable | None":
    return _REGISTRY.get(topic)


def registered_topics() -> set[str]:
    return set(_REGISTRY)
