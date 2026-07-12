# Architecture — Firmosaurus

Event-driven firmware analysis pipeline. Every upload is treated as hostile: it is
unpacked and analyzed at scale, its components are matched against a **local** CVE
corpus with confidence tiering, and findings surface through a dashboard with
grounded, optional AI narration.

The whole backend runs as a single **fat container** on Docker Desktop / WSL2, sized
to survive an 8 GB memory cap. Memory efficiency is the primary design constraint —
the Linux OOM killer is the adversary.

> This document is the map. The authoritative, non-negotiable rules live in
> `.kiro/steering/` (`hard-constraints.md`, `schema.md`, `backend-architecture.md`,
> `analysis-modules-rbac.md`). Where anything here and a steering file disagree, the
> steering file wins.

---

## 1. The fat-container pattern

For local development every backend worker (Triage, Unpack, Analysis, CVE-Match,
Aggregate) runs inside **one** Python container — the `router` process. Splitting into
separate per-stage microservices only happens later via `docker-compose.prod.yml`
(Task 15).

Crucially, this is a deployment choice, not a code choice: handlers communicate
**only** by producing to the next Kafka topic, never by calling each other in-process.
That boundary discipline is what lets the exact same handler code run as one fat
container locally and as four `SERVICES=`-split routers in production with zero code
changes.

- No Celery, anywhere — the router is a pure `confluent-kafka` consumer loop. Celery's
  AMQP/UUID-task model fights Kafka's partition-offset model.
- Sandboxed extraction runs via `subprocess` straight from the handler.
- Periodic CVE-corpus refresh runs via `APScheduler` (not a Celery beat).

## 2. Three-process map (local, `SERVICES=all`)

```
                         ┌──────────────────────────────────────────────┐
                         │                  Redpanda                     │
                         │  (Kafka API; --memory 512M --smp 1)           │
                         └───▲───────────────▲───────────────▲──────────-┘
                             │ produce        │ consume       │ consume (firmware.*)
        presigned upload     │                │               │
  ┌───────────┐  HTTP   ┌────┴───────┐   ┌────┴────────┐  ┌───┴───────────┐
  │  Frontend │────────▶│  gateway   │   │   router    │  │   notifier    │
  │ (native)  │◀────────│ (FastAPI)  │   │ (confluent- │  │ (async WS;    │
  └───────────┘   WS    │            │   │  kafka loop)│  │  own group.id)│
        ▲               └─────┬──────┘   └──────┬──────┘  └───────────────┘
        │                     │                 │
        │ presigned GET/PUT   │ jobs row        │ handlers + binwalk + embeddings
        │              ┌──────┴──────┐   ┌──────┴───────────────────────────┐
        └──────────────│    MinIO    │   │ Redis (counters/markers/locks/    │
                       │ (S3-compat) │   │  idempotency, noeviction)         │
                       └─────────────┘   │ Postgres (+pgvector: jobs,        │
                                         │  cve_corpus, analyst_feedback)    │
                                         │ MongoDB (reports)                 │
                                         └───────────────────────────────────┘
```

1. **gateway** (FastAPI) — upload endpoints + RBAC edge, plus the CVE-matching HTTP
   surface (RAG chat, analyst feedback). Owns presigned MinIO multipart and the
   `jobs` row. Emits `firmware.uploaded` only after the S3 completion callback fires.
2. **router** (`confluent-kafka`) — the poison-pill consumer loop hosting the five
   stage handlers. `binwalk` and the embedding model live here (spare memory headroom
   is parked on this process). Topology is chosen by the `SERVICES` env var.
3. **notifier** (async) — a SEPARATE process with its OWN consumer `group.id`,
   subscribing to `firmware.*` to push per-job progress over WebSocket. It is never a
   `SERVICES` value and is never hosted inside the router.

The **frontend** runs natively on the host (`npm run dev`), never in Docker — which is
why MinIO must advertise `MINIO_SERVER_URL=http://localhost:9000` so presigned URLs
resolve from the host.

## 3. Data flow (pipeline order)

```
 upload (S3 callback)
      │
      ▼
 firmware.uploaded ──▶ [triage]   sha256 + Bloom dedup + magic/size pre-check
      │                              │
      ▼                              ▼
 firmware.triaged ──▶ [unpack]   sandboxed extraction, fan-out per sub-blob,
      │                          INCR total_children, set extraction_complete
      ▼
 firmware.extracted ─▶ [analysis]  strings / entropy / secrets / hardening / versions
   (one per child)                  INCR completed_children
      │
      ▼
 firmware.analyzed ──▶ [cve_match]  CPE exact → embedding fallback → tiering,
      │                             optional LLM triage, write sbom.json,
      ▼                             INCR matched_children
 firmware.matched ───▶ [aggregate]  GATE: matched_children == total_children
      │                             AND extraction_complete → assemble report
      ▼
 firmware.completed                 (report + sbom in MinIO, Mongo upsert, Postgres COMPLETE)

 any handler exception ─▶ firmware.dlq (offset still committed; partition never stalls)
```

### Partition keying (why it matters)

- Job-scoped topics — `uploaded`, `triaged`, `completed`, `dlq` — are keyed by
  `job_id` (one message per job; per-job ordering is fine).
- Fan-out topics — `extracted`, `analyzed`, `matched` — are keyed by **`sub_blob_id`**
  (the child id), NOT `job_id`. Keying these by `job_id` would pin all of a job's
  sub-blobs onto one partition and destroy the horizontal analysis parallelism that is
  the entire point of the fan-out.

### Completion accounting (the gate)

Completion is tracked with Redis counters + a marker, **never** via Kafka ordering:

- `job:{id}:total_children` — incremented by the unpacker as sub-blobs are discovered.
- `job:{id}:completed_children` — incremented at the analysis stage.
- `job:{id}:matched_children` — incremented at the CVE-match stage.
- `job:{id}:extraction_complete` — set once fan-out discovery finishes.

The aggregator fires only when `matched_children == total_children` AND
`extraction_complete` is set. It does **not** gate on `completed_children` — a child
can be analyzed but not yet matched, so gating on the analysis counter fires early.

## 4. Reliability model

- **Kafka commit strategy:** `enable.auto.commit=False` everywhere. Every message is
  processed inside `try/except`; on failure the payload goes to `firmware.dlq` and the
  offset is committed regardless, so one poison message never stalls the partition.
- **Idempotency:** at-least-once delivery means re-delivery happens. Handlers
  check-and-set `processed:{topic}:{message_key}` in Redis before doing work, so a
  replayed message never double-increments a counter.
- **Handler boundary discipline:** handlers never call each other in-process — only
  Kafka produces cross stages.
- **Sandboxing:** extraction uses `setrlimit(RLIMIT_AS)` + wall-clock timeout + SIGKILL,
  with a SIGTERM handler in the parent to reap child processes (no zombies on reload).

## 5. AI framing (air-gapped core, optional narration)

CVE matching is air-gapped: it runs against local `pgvector` with **no network call on
the query path**. The LLM layer is an OPTIONAL external enhancement layered on top —
it explains or ranks a decision the deterministic matcher already made, and is called
ONLY on `POSSIBLE` / `LOW_CONFIDENCE` tiers, never on `CONFIRMED` / `NO_MATCH`. If the
LLM is unavailable, matching still completes; only the narration is omitted. Every AI
call is downstream of a deterministic decision — the LLM never invents a finding.

Embedding model is locked to `sentence-transformers/all-MiniLM-L6-v2` (384-dim);
`cve_corpus.embedding` and the per-job RAG index are both `vector(384)`. Model and
dimension change together, never one alone.

## 6. Data stores

| Store | Role |
|---|---|
| Redpanda | Kafka-API message broker (the pipeline spine) |
| Redis (single, `noeviction`) | Structural state only: counters, markers, Redlock, idempotency, Bloom bitmap |
| Postgres (+pgvector) | `jobs`, `cve_corpus` (`vector(384)`), `analyst_feedback` |
| MongoDB | `reports` (one flexible document per job) |
| MinIO | Object store: `raw-uploads`, `extracted/`, `reports/` (report + sbom) |

## 7. Contract as code (drift-proof)

`shared/` is the frozen interface every group imports:

- `shared/contracts/` — one Pydantic model per event (SCHEMA.md §2), `extra="forbid"`
  so schema drift is a loud validation error, not a silent mystery bug. Handlers
  validate payloads IN and OUT.
- `shared/topics.py` — topic-name constants (no magic strings).
- `shared/redis_keys.py` — key builders that pin the exact key patterns.

Changes to `shared/`, `SCHEMA.md`, `docker-compose.yml`, `services/router/Dockerfile`,
or `.kiro/steering/` require a flagged PR reviewed across affected groups. See
`CONTRIBUTING.md`.
