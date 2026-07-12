# Firmosaurus

An event-driven firmware analysis pipeline. It treats every uploaded firmware image as
hostile, unpacks and analyzes it at scale, matches discovered components against a
**local** CVE corpus with confidence tiering, and surfaces findings through a dashboard
with grounded, optional AI narration.

Built to run as a single "fat container" on Docker Desktop / WSL2 under an 8 GB memory
cap — memory efficiency is the primary constraint throughout.

## What it does

- **Ingest** — presigned MinIO upload; a `jobs` row is created and `firmware.uploaded`
  is emitted only after the storage completion callback.
- **Triage** — SHA256 + a real Bloom-filter dedup + magic-byte / size pre-check.
- **Unpack** — sandboxed extraction (`setrlimit` + timeout + SIGKILL) with layered
  zip-bomb defenses, fanning out one message per discovered sub-blob.
- **Analyze** — multi-encoding strings, per-section entropy, secret/key detection,
  binary hardening flags, and version candidates.
- **Match** — normalize to CPE, exact lookup then embedding fallback against local
  `pgvector`, confidence tiering, optional LLM triage on ambiguous tiers, plus an
  `sbom.json` artifact.
- **Aggregate** — assemble the final report once every child is matched, persist to
  MongoDB + MinIO, and emit `firmware.completed`.
- **Notify** — per-job live progress over WebSocket.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the process map and data flow.

## Repository layout

```
shared/            # frozen contract: Pydantic event models, topic names, redis key builders
services/
  gateway/         # FastAPI: upload + RBAC edge, CVE HTTP surface (RAG chat, feedback)
  router/          # confluent-kafka poison-pill loop hosting the stage handlers
    handlers/      # triage / unpack / analysis / cve_match / aggregate
  notifier/        # async WebSocket progress (own consumer group)
frontend/          # native React/Next.js (runs on host, never in Docker)
scripts/           # emit/consume test harness
sample_payloads/   # one canonical JSON per topic — the executable spec
docker-compose.yml # local infra (Redpanda, Redis, Postgres+pgvector, MongoDB, MinIO)
```

Authoritative rules live in `.kiro/steering/` (`hard-constraints.md`, `schema.md`,
`backend-architecture.md`, `analysis-modules-rbac.md`). They win over any other doc.

## Prerequisites

- Docker Desktop with WSL2 integration (WSL2 capped at 8 GB via `.wslconfig`).
- Python 3.11+ (for the harness/router) and Node 18+ (for the frontend).
- `rpk` / `mc` / `redis-cli` / `psql` are handy for the verification steps but optional.

## Quickstart

```bash
# 1. Configure environment
cp .env.example .env          # then fill in secrets (LLM_API_KEY, passwords, JWT_SECRET)

# 2. Bring up local infrastructure
docker compose up -d

# 3. Sanity-check the stack (all should succeed) — run against the containers
docker exec firmosaurus-redpanda rpk cluster info -X brokers=localhost:9092
docker exec firmosaurus-redis redis-cli CONFIG GET maxmemory-policy        # -> noeviction
docker exec firmosaurus-postgres psql -U firmosaurus -d firmosaurus \
  -c "CREATE EXTENSION IF NOT EXISTS vector;"
docker exec firmosaurus-minio mc ls local/raw-uploads                      # bucket exists
docker stats --no-stream                                                   # total RSS well under 8 GB

# 4. Exercise the message harness (round-trip a sample payload)
python scripts/consume_topic.py firmware.triaged     # in one terminal
python scripts/emit_test_event.py firmware.triaged sample_payloads/firmware.triaged.json
```

## Running the backend

The router selects which handlers it hosts via the `SERVICES` env var:

```bash
# local fat mode: one process hosts every stage
SERVICES=all python -m services.router.runner

# or a subset
SERVICES=triage,unpack python -m services.router.runner
```

Valid `SERVICES` values: `triage`, `unpack`, `analysis`, `match`, `aggregate`, `all`
(comma-combos allowed). The notifier is a separate process, never a `SERVICES` value.

## Contributing

Group-branch workflow, PR rules, and commit conventions are in
[`CONTRIBUTING.md`](./CONTRIBUTING.md). The shared-interface files (`shared/`,
`SCHEMA.md`, `docker-compose.yml`, `services/router/Dockerfile`, `.kiro/steering/`) are
PR-gated and require cross-group review.
