"""Backend services (fat-container pattern).

Three processes share this package: `gateway` (FastAPI upload + RBAC + CVE HTTP
surface), `router` (confluent-kafka poison-pill loop hosting the stage handlers),
and `notifier` (WebSocket progress). See ARCHITECTURE.md and
`.kiro/steering/backend-architecture.md`.
"""
