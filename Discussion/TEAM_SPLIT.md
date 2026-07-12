# TEAM_SPLIT.md — Group Ownership, Task Map & Workflow

Team size: 3–4 people, organized into **4 groups**. Timeline: **3–4 days**, Kiro Pro.
Backend is built first (independently testable per group against `sample_payloads/`);
frontend is built last. This file maps the 15 tasks in `IMPLEMENTATION_PLAN.md` to
groups and defines the file-ownership boundaries that keep the groups from colliding.

The backend is a single **fat container** using the router/handlers layout — there is NOT
one top-level folder per group. Ownership is at the **file level**, and the router uses
**decorator auto-registration** (`@register(topic)`) so there is no shared handler dict to
merge-conflict on.

---

## 0. Prerequisite — Contract Freeze (before anyone writes handler code)

One session, whole team, before group work begins:

- [ ] Finalize and merge `SCHEMA.md` (all Kafka event shapes, Redis key names incl.
      `total_children` / `completed_children` / `matched_children`, Postgres/Mongo shapes)
- [ ] Land `shared/contracts/` (Pydantic model per event), `shared/topics.py`,
      `shared/redis_keys.py` — handlers validate payloads IN and OUT against these
- [ ] Agree RBAC role names (`admin` / `analyst` / `reader`) and where each is enforced
- [ ] Everyone commits at least one hand-written sample JSON payload per topic they
      consume into `sample_payloads/`, matching `SCHEMA.md` exactly

**Rule:** once merged, changes to `SCHEMA.md` / `shared/contracts/` require a PR reviewed by
at least one person from every affected group. These are the team's shared interface and
must never be edited unilaterally mid-sprint.

---

## Repo layout (file-level ownership)

```
shared/                     # Group 1 owns; others import, edit only via flagged PR
  contracts/                #   Pydantic model per event
  topics.py                 #   topic-name constants
  redis_keys.py             #   key builders (total/matched/extraction_complete, locks)
services/
  gateway/                  # Group 2 (upload/RBAC) + Group 3 (CVE HTTP surface)
  router/
    Dockerfile              # SHARED, PR-gated: Group 1 seeds base image (Python + confluent-kafka);
                            #   Group 2 adds binwalk + extraction backends via a flagged PR
    runner.py               # Group 1 — SERVICES loop, poison-pill/DLQ, decorator registration
    handlers/
      triage.py             # Group 2
      unpack.py             # Group 2
      analysis.py           # Group 2
      cve_match.py          # Group 3
      aggregate.py          # Group 3
  notifier/                 # Group 3
frontend/                   # Group 4 (runs natively on host, never in Docker)
scripts/                    # Group 1 (emit/consume harness)
sample_payloads/            # Group 1 seeds; every group adds its own, additive-only
docker-compose.yml          # Group 1; any change is its own small, fast-review PR
```

Because ownership is per-file and handlers self-register via decorator, two people are
almost never editing the same file. The usual conflict magnets — `docker-compose.yml`,
`SCHEMA.md`, `shared/contracts/`, and `services/router/Dockerfile` — are explicitly PR-gated,
narrow-scope changes.

**Router Dockerfile (shared, PR-gated):** Group 1 seeds the base router image (Python +
`confluent-kafka` + shared deps) as part of the router skeleton. Group 2 must extend that same
image with `binwalk` + pinned extraction backends (needed by `unpack.py`) — so the Dockerfile is
a shared file both groups touch. Any change to it is a flagged, fast-review PR, not a silent
edit, so it never becomes a surprise merge point.

---

## Group 1 — Foundation & Shared Baseline (lands on `main` first)

**Owns:** `shared/`, `services/router/runner.py`, `scripts/`, `docker-compose.yml`,
`sample_payloads/` seeds, CI gate.
**Merges first** — every other group branches from Group 1's baseline.
**Tasks 1–4.**

### Checklist
- [ ] Task 1 — Repo baseline + frozen contract-as-code: `SCHEMA.md`, `shared/contracts/`,
      `shared/topics.py`, `shared/redis_keys.py`, `ARCHITECTURE.md`, this `TEAM_SPLIT.md`,
      `.kiro/steering/hard-constraints.md` (inclusion: always) + per-group context files,
      `README.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `.gitignore`, `.env.example`
- [ ] Task 2 — `docker-compose.yml` with memory discipline: Redpanda flags
      (`--overprovisioned --memory 512M --reserve-memory 0M --smp 1`), per-service
      `mem_limit`, single `noeviction` Redis, MinIO `raw-uploads` 24h lifecycle +
      `MINIO_SERVER_URL`, pgvector extension on init; verify `docker stats` under 8GB
- [ ] Task 3 — Shared harness + sample payloads: `scripts/emit_test_event.py`,
      `scripts/consume_topic.py`, canonical `sample_payloads/` for every event type
- [ ] Task 4 — Router skeleton + CI gate: `runner.py` with `SERVICES` subscription,
      `enable.auto.commit=False` poison-pill loop, DLQ routing, Redis check-and-set
      idempotency helper, decorator auto-registration; wire CI checks

---

## Group 2 — Ingestion & Extraction (parallel with Group 3, against `sample_payloads/`)

**Owns:** `services/gateway/` (upload + RBAC), `services/router/handlers/triage.py`,
`unpack.py`, `analysis.py`, Postgres `jobs` table.
**Depends on:** Group 1's baseline + a sample `firmware.triaged` payload (does NOT need
Group 3 running).
**Produces:** `firmware.uploaded`, `firmware.triaged`, `firmware.extracted`, `firmware.analyzed`.
**Tasks 5–8.**

### Checklist
- [ ] Task 5 — Upload Gateway + 3-tier RBAC: presigned MinIO multipart, job row
      (`status=UPLOADED`), emit `firmware.uploaded` ONLY after the S3 completion callback,
      dual MinIO clients (presign localhost:9000 vs internal minio:9000), inlined JWT,
      all three role boundaries enforced
- [ ] Task 6 — Triage handler: SHA256, REAL Bloom filter (k hashes via double hashing over
      a Redis bitmap, sized for target FPR), magic-byte + declared-size pre-check →
      `firmware.triaged` or `firmware.dlq` (reason code). Reviewer check: k>1, distinct bits
- [ ] Task 7 — Unpacker: `setrlimit(RLIMIT_AS)` + wall-clock timeout + SIGKILL subprocess;
      four zip-bomb layers (zip-slip, symlink, recursion depth, decompression-ratio watchdog);
      fan-out `firmware.extracted` keyed by child id; `INCR total_children`; set
      `extraction_complete` marker; job_id-namespaced temp + try/finally cleanup; pinned binwalk
- [ ] Task 8 — Static Analysis: multi-encoding strings (ASCII + UTF-16LE/BE), per-section
      entropy, secret/key regex pass, hardening flags (checksec/ELF), version candidates;
      emit `firmware.analyzed`; `INCR completed_children`

---

## Group 3 — Intelligence & Aggregation (parallel with Group 2, against `sample_payloads/`)

**Owns:** `services/router/handlers/cve_match.py`, `aggregate.py`, `services/notifier/`,
the CVE HTTP surface in `services/gateway/` (RAG chat, feedback), CVE corpus ETL.
**Depends on:** Group 1's baseline + a sample `firmware.analyzed` payload.
**Produces:** `firmware.matched`, `firmware.completed`.
**Tasks 9–12.**

### Checklist
- [ ] Task 9 — CVE corpus ETL + refresh: bulk NVD feed, scope to component families, embed
      into pgvector, build index, incremental refresh via **APScheduler** (NOT Celery, NOT a
      nightly beat). No network on the query path
- [ ] Task 10 — CVE Matching + AI triage: regex normalize → CPE, exact lookup then embedding
      fallback, confidence tiering, LLM triage ONLY for `POSSIBLE`/`LOW_CONFIDENCE`, exec
      summary; emit `firmware.matched`; `INCR matched_children`; write `sbom.json`
- [ ] Task 11 — Report Aggregator + DLQ/replay: gate on
      `matched_children == total_children` AND `extraction_complete` marker (NOT
      `completed_children`); idempotent Mongo upsert by `job_id`; upload report + sbom to
      MinIO; Postgres `COMPLETE`; emit `firmware.completed`; DLQ exponential-backoff retry
      under Redlock
- [ ] Task 12 — WebSocket Notification Gateway: OWN consumer `group.id`; consume `firmware.*`;
      per-job progress push; backpressure handling

---

## Group 4 — Surface & Integration (after Groups 2 and 3 merge)

**Owns:** `frontend/` (native React/Next.js), final integration wiring, production profile.
**Depends on:** Groups 2 and 3 merged to `main` (reads real endpoint/WS shapes).
**Produces:** the end-to-end demo.
**Tasks 13–15.**

### Checklist
- [ ] Task 13 — Frontend: presigned upload, job list, live progress via WebSocket, report
      viewer (tiers, SBOM, hardening, secrets), RBAC-aware UI, scoped RAG chat; three role views
- [ ] Task 14 — Feedback loop + RAG lifecycle: confirm/false-positive endpoint +
      `analyst_feedback` table, per-component-family threshold recalibration, per-job vector
      index build/teardown, cross-job chat isolation
- [ ] Task 15 — Final integration + production profile: wire all three processes for a real
      no-mock run; `docker-compose.prod.yml` (four `SERVICES=`-split routers); recompute
      mem-budget table against 8GB (headroom parked on router); `.vhdx` compaction runbook

---

## Shared Test Harness (Group 1 builds this on day 1 — unblocks Groups 2 and 3)

```python
# scripts/emit_test_event.py
# Usage: python emit_test_event.py firmware.triaged sample_payloads/triaged_1.json
import sys, json
from confluent_kafka import Producer
producer = Producer({'bootstrap.servers': 'localhost:19092'})
topic = sys.argv[1]
payload = json.load(open(sys.argv[2]))
producer.produce(topic, json.dumps(payload).encode())
producer.flush()
print(f"Emitted to {topic}")
```

```python
# scripts/consume_topic.py
# Usage: python consume_topic.py firmware.analyzed
import sys, json
from confluent_kafka import Consumer
c = Consumer({'bootstrap.servers': 'localhost:19092', 'group.id': 'debug', 'auto.offset.reset': 'earliest'})
c.subscribe([sys.argv[1]])
while True:
    msg = c.poll(1.0)
    if msg: print(json.loads(msg.value()))
```

This pair is what makes "Group 2 and Group 3 don't need each other running" true in practice.
Group 1 ships it before deep work starts anywhere else.

---

## Workflow — Preventing Clashes & Keeping Things Fluid

### Branching model
- `main` — protected, holds the shared baseline. Merges only via PR with owning-group review
  (CODEOWNERS) + green CI.
- **Group 1 merges to `main` first.** Everyone else branches from that baseline.
- `group2/ingestion` and `group3/intelligence` branch from `main` and run **in parallel**
  against `sample_payloads/`.
- `group4/surface` branches **after** Groups 2 and 3 merge (it reads their real shapes).
- Short-lived feature branches off your group branch for individual pieces
  (e.g. `group2/ingestion/zip-bomb-defenses`); merge to your group branch freely, merge the
  group branch → `main` at agreed sync points.

### CI gate (enforced on every PR)
- **Schema-lint:** every file in `sample_payloads/` validates against `shared/contracts/`.
- **Reviewer checks:** Bloom filter uses k>1 distinct bits; the aggregator gates on
  `matched_children` (not `completed_children`); no direct handler-to-handler calls
  (inter-stage communication is Kafka-only).

### Async sync
- A shared status channel where each person posts one line at the end of a work session:
  *what topic am I producing now, is its shape still matching `SCHEMA.md`.* This alone
  prevents the most common failure mode — someone silently changing a field name and nobody
  noticing until integration.
- If `SCHEMA.md` / `shared/contracts/` needs to change (it will, at least once), that's a
  same-day PR + ping to all affected groups, never a silent local change.

### Integration checkpoints (compressed 3–4 day schedule)
- **Day 1:** Group 1's baseline (`shared/`, compose, harness, router skeleton) merged to
  `main`; Groups 2 and 3 branch and start against `sample_payloads/`.
- **Day 2:** Groups 2 and 3 each process a hand-written sample end-to-end within their own
  handlers; Group 2's upload flow works standalone.
- **Day 3:** first real chain — Group 2's real `firmware.analyzed` fed into Group 3's matcher,
  no sample substitution; Groups 2 and 3 merge to `main`; Group 4 branches.
- **Day 4:** full real chain A→D on one real firmware file; frontend integration + bug-fix buffer.

### Avoiding schema drift (the #1 team-project failure mode)
- Every handler validates payloads IN and OUT against `shared/contracts/` (Pydantic) — this
  turns silent drift into a loud, immediate error, far cheaper to fix than a mystery bug on day 4.
- `sample_payloads/` is the executable spec. If there's ever a disagreement about a field, the
  sample file wins and `SCHEMA.md` is corrected to match (or vice versa, but explicitly, via PR).

### Code review norms
- Reviews within your own group: fast, informal, same-day.
- Reviews touching `shared/contracts/`, `SCHEMA.md`, `docker-compose.yml`,
  `services/router/Dockerfile`, or the `.kiro/steering/` files: require a reviewer from a
  *different* group — these are the shared-interface files everyone depends on.
