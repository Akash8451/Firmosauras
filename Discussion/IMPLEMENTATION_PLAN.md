# Firmosaurus — Implementation Plan (v2, locked)

## Overview
Event-driven firmware analysis pipeline. Treats every upload as hostile; unpacks
and analyzes at scale; matches components against a LOCAL CVE corpus with
confidence tiering; surfaces findings through a dashboard with grounded AI.
Runs as a single "fat container" on Docker Desktop/WSL2.

- Host: 16GB Windows / WSL2 cap = 8GB
- Timeline: 3-4 days, Kiro Pro
- Structure: 4 groups, 15 tasks
- GitHub: protected `main` + group-level branches

## Locked decisions & correctness fixes
- Completion accounting: increment `matched_children` at the CVE-match stage.
  Aggregator gates on `matched_children == total_children` AND `extraction_complete`
  marker. (Do NOT gate on the analysis-stage `completed_children`.)
- Partition keying: fan-out topics (firmware.extracted/analyzed/matched) keyed by
  child/sub-blob id, NOT job_id. Completion via Redis counter + marker, never Kafka ordering.
- Bloom filter: real filter over a Redis bitmap — k hash functions via double hashing
  (bit_i = (h1 + i*h2) mod m), m/k sized for target FPR at expected n. NOT a single-bit hash set.
- Redpanda: MUST run with `--overprovisioned --memory 512M --reserve-memory 0M --smp 1`
  (mandatory even at 8GB; mem_limit alone is insufficient).
- Sandbox: resource.setrlimit(RLIMIT_AS) + wall-clock timeout + SIGKILL. NO in-container cgroups.
- NO Celery. Subprocess for extraction; APScheduler for CVE refresh.
- Single Redis instance, `noeviction` (all state is structural; no cache tier).
- Schema-first: contract frozen before any handler is written.
- AI framing: air-gapped CVE matching (local pgvector, NO network on the query path) is the
  core; LLM narration is an OPTIONAL external enhancement layered on top, not part of the
  air-gapped core. LLM called ONLY on POSSIBLE/LOW_CONFIDENCE tiers, never CONFIRMED/NO_MATCH;
  if the LLM is unavailable, matching still completes without narration.
- Embedding model (locked in Group 1/Task 1): sentence-transformers/all-MiniLM-L6-v2 → 384-dim.
  pgvector fixes dimension at table creation, so cve_corpus.embedding and the per-job RAG index
  are both vector(384). Model + dimension change together, never one alone.
- LLM provider (FREE tiers only, OpenAI-compatible, swappable via env): default Groq
  llama-3.3-70b-versatile; failover Gemini gemini-2.5-flash-lite. Configured via
  LLM_PROVIDER/LLM_MODEL/LLM_BASE_URL/LLM_API_KEY in .env (gitignored); .env.example ships key
  names only. Never hardcode or commit keys.
- MinIO: separate presign client (localhost:9000) vs internal-ops client (minio:9000).
- Pin binwalk + extraction-backend versions. Inline JWT/RBAC (no external references).

## Local process map (fat mode, SERVICES=all)
1. gateway (FastAPI): upload endpoints + CVE-matching HTTP surface (RAG chat, feedback).
2. router (confluent-kafka): poison-pill loop hosting triage/unpack/analysis/cve-match/aggregate
   handlers; binwalk + embedding model live here (extra 8GB headroom parked here).
3. notifier (async, OWN consumer group): WebSocket progress from firmware.*.
Frontend runs natively on host (npm run dev), never in Docker.

## Contract as code (drift-proof)
- shared/contracts/  — Pydantic models per event; handlers validate in AND out.
- shared/topics.py   — topic-name constants (no magic strings).
- shared/redis_keys.py — key builders (total_children, matched_children,
  extraction_complete, lock keys).

## Repo layout (file-level ownership)
shared/            # Group 1 owns; others import, edit only via flagged PR
services/
  gateway/         # Group 2 (upload/RBAC) + Group 3 (cve HTTP surface)
  router/
    handlers/
      triage.py    # Group 2
      unpack.py    # Group 2
      analysis.py  # Group 2
      cve_match.py # Group 3
      aggregate.py # Group 3
    runner.py      # Group 1; decorator auto-registration (@register(topic))
  notifier/        # Group 3
frontend/          # Group 4
scripts/           # Group 1
sample_payloads/   # Group 1 seeds; groups add their own

Router uses decorator auto-registration so there is NO shared TOPIC_HANDLERS dict to
merge-conflict on.

## Branching & CI
- main protected, holds the shared baseline. Group 1 merges first.
- Group-level branches: group2/ingestion + group3/intelligence branch from main and run
  in parallel against sample_payloads/. group4/surface branches after 2 and 3 merge.
- PRs require owning-group review (CODEOWNERS) + green CI.
- CI gate: schema-lint (payloads validate against shared/contracts/) + reviewer checks
  (k>1 distinct Bloom bits; matched_children used at aggregation; no direct
  handler-to-handler calls).

## Guiding principles
AI always downstream of a deterministic decision; recall-biased with confidence tiering;
independent defensive layers; mandatory idempotency; isolated structural state (noeviction);
local/offline-first CVE data; explicit acknowledgment of static-analysis limits.

---

# TASKS

## Group 1 — Foundation & Shared Baseline (lands on main first)

### Task 1: Repo baseline + frozen contract-as-code
Objective: single source of truth every group imports.
Deliverables: SCHEMA.md (frozen; pins embedding model all-MiniLM-L6-v2 → vector(384) and the
LLM provider/env-var names); shared/contracts/ (Pydantic per event);
shared/topics.py; shared/redis_keys.py; ARCHITECTURE.md; TEAM_SPLIT.md (task map +
file-ownership boundaries); .kiro/steering/hard-constraints.md (inclusion: always) +
per-track context files; README.md; CONTRIBUTING.md; CODEOWNERS; .gitignore; .env.example.
Test: schema-lint validates sample_payloads/ against shared/contracts/ in CI.
Demo: clone main, import shared/, on-contract immediately.

### Task 2: docker-compose.yml infra with memory discipline
Redpanda flags; per-service mem_limit; single noeviction Redis; MinIO raw-uploads 24h
lifecycle + MINIO_SERVER_URL; pgvector extension on init.
Test: rpk cluster info / psql extension / mc bucket checks + docker stats under 8GB.
Demo: one shared healthy infra stack.

### Task 3: Shared harness + sample payloads
scripts/emit_test_event.py, scripts/consume_topic.py, canonical sample_payloads/ for
every event type.
Test: emit → consume → round-trip equality.
Demo: produce/consume a dummy event.

### Task 4: Router skeleton + CI gate
runner.py: SERVICES subscription, enable.auto.commit=False poison-pill loop, DLQ routing,
Redis check-and-set idempotency helper, decorator auto-registration. Wire CI checks.
Test: valid → routed + committed; malformed → DLQ, partition not stalled.
Demo: full message journey in one log; poison quarantined.

## Group 2 — Ingestion & Extraction (parallel with Group 3, against sample_payloads/)

### Task 5: Upload Gateway + 3-tier RBAC (admin/analyst/reader)
Presigned MinIO multipart; job row (status=UPLOADED); emit firmware.uploaded ONLY after
S3 completion callback; dual MinIO clients; inlined JWT.
Test: upload flow + auth + all three role boundaries + no-early-emit.
Demo: presigned upload, job row, event; reader denied upload.

### Task 6: Triage handler
SHA256; REAL Bloom filter (k hashes via double hashing, sized for target FPR);
magic-byte + declared-size pre-check → firmware.triaged or firmware.dlq (reason code).
Test: measured FPR within bound on disjoint set; never a false negative; dedup works.
Reviewer check: k>1, distinct bits.
Demo: duplicate upload flagged.

### Task 7: Unpacker Service
setrlimit(RLIMIT_AS) + timeout + SIGKILL subprocess; four zip-bomb layers (zip-slip,
symlink, recursion depth, decompression-ratio watchdog); fan-out firmware.extracted keyed
by child id; INCR total_children; set extraction_complete marker; job_id-namespaced temp;
try/finally cleanup; pinned binwalk backends.
Test: benign nested archive → N events + counter + marker + cleanup; zip bomb killed +
DLQ + cleanup; zip-slip rejected.
Demo: fan-out succeeds; bomb killed mid-extraction.

### Task 8: Static Analysis Workers
Multi-encoding strings (ASCII + UTF-16LE/BE); per-section entropy; secret/key regex pass;
hardening flags (checksec/ELF); version candidates; emit firmware.analyzed;
INCR completed_children.
Test: fully-populated event matching schema; UTF-16 not garbled; planted key flagged.
Demo: strings + entropy + secrets + hardening flags in one event.

## Group 3 — Intelligence & Aggregation (parallel with Group 2, against sample_payloads/)

### Task 9: CVE corpus ETL + refresh
Bulk NVD feed; scope to component families; embed with all-MiniLM-L6-v2 (384-dim) into
pgvector vector(384) column; build index; incremental refresh via APScheduler (NOT Celery).
Test: known CPE resolves in ms; refresh ingests new record; NO network on query path.
Demo: offline BusyBox CVE lookup.

### Task 10: CVE Matching + AI triage
Regex normalize → CPE; exact lookup then embedding fallback; confidence tiering; LLM triage
(free Groq llama-3.3-70b-versatile via env, OpenAI-compatible) ONLY for POSSIBLE/LOW; exec
summary; emit firmware.matched; INCR matched_children; write sbom.json.
Test: correct tiering; no LLM on CONFIRMED/NO_MATCH; matched_children increments.
Demo: messy version string → right tier + grounded explanation.

### Task 11: Report Aggregator + DLQ/replay
Gate on matched_children == total_children AND extraction_complete marker; idempotent Mongo
upsert by job_id; upload report + sbom to MinIO; Postgres COMPLETE; emit firmware.completed;
DLQ exponential-backoff retry under Redlock.
Test: exactly one report per job; replay-safe; DLQ retry under lock.
Demo: full job via harness; replayed safely.

### Task 12: WebSocket Notification Gateway
Own consumer group.id; consume firmware.*; per-job progress push; backpressure handling.
Test: incremental X/N updates; slow client doesn't block others.
Demo: live "14/40 analyzed".

## Group 4 — Surface & Integration (after Groups 2/3 merge)

### Task 13: Frontend (native React/Next.js)
Presigned upload; job list; live progress via WebSocket; report viewer (tiers, SBOM,
hardening, secrets); RBAC-aware UI; scoped RAG chat. Read real endpoint/WS shapes.
Test: three role views; chat shows its job scope.
Demo: end-to-end for all three roles.

### Task 14: Feedback loop + RAG lifecycle
Confirm/false-positive endpoint + analyst_feedback table; per-component-family threshold
recalibration; per-job vector index build/teardown.
Test: false-positive shifts that family's threshold; cross-job chat isolation.
Demo: correct a match; watch threshold move.

### Task 15: Final integration + production profile
Wire all three processes for a real no-mock run; docker-compose.prod.yml (four SERVICES=-split
routers); recompute mem-budget table against 8GB (headroom on router); .vhdx compaction runbook.
Test: full upload → report-in-UI; docker stats under 8GB.
Demo: same code as one fat container AND as four scaled containers.
