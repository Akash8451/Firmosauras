# Design: Firmware Analysis Pipeline (v2)

> **⚠ Superseded on some points by `IMPLEMENTATION_PLAN.md` and `.kiro/steering/` — those are authoritative (8GB, no Celery, single Redis, `matched_children`).** This document is retained as design rationale; where it conflicts with the plan or the steering files, the plan/steering win.

A distributed, event-driven system that ingests untrusted firmware binaries, safely unpacks and analyzes them at scale, matches components against known vulnerabilities, and surfaces findings through a full-stack dashboard with a grounded AI layer. This document captures the complete design discussion, decisions, and rationale.

---

## 1. Core Concept

Process firmware binaries (router firmware, IoT blobs, etc.) through a pipeline that treats every input as **hostile by default**. The core engineering challenge isn't "process a file" — it's "process a file you don't trust, at scale, without one malicious upload taking down your workers."

**Key differentiator vs. v1 (RabbitMQ version):** This version is deliberately built around **Kafka** as the backbone rather than RabbitMQ, to prove a different set of distributed systems skills (ordered logs, consumer groups, replayability) rather than repeating the smart-broker/task-queue pattern already demonstrated.

---

## 2. Microservices Boundary Map

| Service | Responsibility | Tech |
|---|---|---|
| **Upload Gateway** | Accepts firmware upload, validates JWT/RBAC, generates presigned S3 multipart URL, writes job metadata to Postgres, emits `firmware.uploaded` to Kafka | FastAPI |
| **Triage Worker** | Consumes `firmware.uploaded`. Computes hash, checks Redis Bloom filter for dedup, checks file magic bytes/size against policy (zip bomb pre-check), routes to `firmware.triaged` or DLQ | confluent-kafka router handler (`triage.py`) |
| **Unpacker Service** | Runs extraction in a sandboxed/resource-limited subprocess (RLIMIT_AS cap + wall-clock timeout + SIGKILL), emits one `firmware.extracted` event per discovered sub-blob (fan-out) | confluent-kafka handler + subprocess sandboxing |
| **Static Analysis Workers** (scaled pool) | Consumes `firmware.extracted`, does string extraction, entropy analysis per section, architecture detection | confluent-kafka handler, CPU-bound, horizontally scaled |
| **CVE/Hash Matching Service** | Matches extracted component versions against known-vulnerable component data (exact CPE + fuzzy embedding similarity) | FastAPI + pgvector/Postgres |
| **Report Aggregator** | Tracks fan-out completion via Redis counters, assembles final report, persists to MongoDB, writes artifact to S3 | confluent-kafka handler + Redis + MongoDB |
| **Notification Gateway** | Pushes live job progress to the user's dashboard | WebSocket |
| **DLQ/Replay Service** | Handles anything that fails triage, times out, or throws during analysis — manual replay or auto-retry with backoff | Kafka DLQ topic + admin tooling |

---

## 3. Data-Flow Blueprint

```
[User] --JWT auth--> [Upload Gateway]
                            │
                    presigned multipart URL --> S3 (raw firmware blob)
                            │
                    writes job row --> Postgres (job_id, status=UPLOADED)
                            │
                    produces --> Kafka topic: firmware.uploaded (key = job_id)

[Triage Worker] consumes firmware.uploaded
        ├─ SHA256 hash --> Redis Bloom filter check (O(1) dedup)
        ├─ magic-byte + declared-size sanity check (zip bomb pre-check)
        ├─ if suspicious --> produce to firmware.dlq (with reason code)
        └─ if clean --> produce firmware.triaged

[Unpacker Service] consumes firmware.triaged
        ├─ extraction in a resource-capped subprocess (RLIMIT_AS / cgroup mem cap + wall-clock timeout)
        ├─ decompression-ratio watchdog: kill subprocess if output/input ratio exceeds threshold mid-extraction
        ├─ for each extracted sub-blob --> upload to S3 --> produce firmware.extracted
        └─ INCR job:{job_id}:total_children in Redis

[Static Analysis Workers] (N parallel consumers, same consumer group)
        ├─ entropy analysis per section (flags packed/encrypted regions)
        ├─ multi-encoding string extraction (ASCII + UTF-16LE/BE)
        ├─ produce firmware.analyzed
        └─ INCR job:{job_id}:completed_children in Redis

[CVE Matching Service] consumes firmware.analyzed
        ├─ normalize extracted version strings into CPE tuples (regex per component family)
        ├─ exact CPE lookup first (local Postgres/pgvector table)
        ├─ fallback: embed messy/unmatched strings, similarity search against local corpus
        └─ produce firmware.matched (tagged with confidence tier)

[Report Aggregator] consumes firmware.matched
        ├─ check Redis: completed_children == total_children AND extraction-complete marker set?
        │      NO  --> persist partial result to Mongo, wait
        │      YES --> assemble full report, write to Mongo, upload artifact to S3, mark Postgres job COMPLETE
        └─ produce firmware.completed

[Notification Gateway] consumes firmware.* (all topics, for progress) --> WebSocket push: "14/40 done"

[DLQ/Replay Service] consumes firmware.dlq
        └─ exponential backoff retry, or surfaces to admin review after N failures
```

**JWT** carries role claims (`analyst`, `admin`, etc.) validated at the Upload Gateway edge — standard HS256 JWT with role claims, pattern documented in SCHEMA.md §5.

**S3** serves as both raw-blob storage and the event-sourcing cold-store for final report artifacts.

---

## 4. Why Kafka Over RabbitMQ This Time (interview-ready justification)

- **RabbitMQ** = smart broker, per-message routing, task-queue semantics, natural DLQ support — good fit for the original firmware pipeline's targeted job routing/retry needs.
- **Kafka** = dumb broker/log, ordered partitions, consumer groups, **replayability** — better where multiple services need to independently consume and where a crashed consumer needs to rebuild state from a retained log.
- Specific justification here: the fan-out from one firmware blob into many sub-blobs, each needing independent horizontally-scaled analysis, plus an aggregator that must accurately recount completions — if the Report Aggregator crashes mid-count, it can **replay `firmware.analyzed` from the last committed offset** and rebuild state instead of losing acknowledged messages. RabbitMQ's ephemeral queue model doesn't give you this replay guarantee as naturally.

---

## 5. Redis's Three Distinct Roles (name them separately, don't conflate)

1. **Bloom filter** — O(1) dedup at triage, avoids reprocessing identical firmware.
2. **Distributed counter** — `total_children` / `completed_children` per job, lets the aggregator know fan-out completion without polling Postgres.
3. **Distributed lock (Redlock)** — prevents two workers from double-claiming the same DLQ retry simultaneously.

**Isolation requirement:** structural state (counters, locks, Bloom filter) must live on a `noeviction` Redis instance/DB, separate from any cache-able data — otherwise memory pressure can silently evict critical state under an LRU policy.

---

## 6. Zip Bomb / Malicious Archive Defense (layered, not single-point)

Defense must be layered because no single check is sufficient:

1. **Pre-check**: magic-byte + declared-size sanity check before extraction even starts.
2. **Path sanitization (zip slip defense)**: reject any archive entry whose resolved path escapes the sandboxed extraction root (defends against `../../etc/cron.d/evil`-style entries).
3. **Symlink defense**: disable symlink following during extraction, or resolve-and-reject any symlink pointing outside the sandbox.
4. **Recursion depth cap**: independent of size-based checks — defends against zip-in-zip-in-zip nesting attacks that exhaust stack/inodes even when each individual archive looks small.
5. **Resource-capped subprocess**: cgroup memory + CPU caps and a hard wall-clock timeout (SIGKILL, not just SIGTERM — corrupted firmware can make extraction tools hang, and SIGTERM can be ignored).
6. **Decompression-ratio watchdog**: kill the subprocess mid-extraction if output/input ratio exceeds a threshold — this is the real defense against bombs that pass the pre-check but reveal themselves only during extraction.

---

## 7. Pragmatic AI Integration — 5 Distinct, Load-Bearing Touchpoints

Explicit design principle to state in interviews: **every AI call in this system is downstream of a deterministic decision, never upstream of one.** The AI explains or ranks; it never invents the security verdict.

| Stage | AI Role | Why it's not a toy wrapper |
|---|---|---|
| **CVE/version matching** | Embed extracted version strings, similarity-search against a local CVE corpus in pgvector | Vulnerability decision comes from retrieval, not LLM guesswork |
| **String triage/classification** | Classifier/embedding clustering auto-tags extracted strings as credentials, URLs, crypto material, or noise | Cuts analyst review time from thousands of raw strings to a ranked list |
| **Entropy anomaly detection** | Classifier over section entropy signatures distinguishes packed/encrypted regions more reliably than a fixed threshold | Reduces false-positive flood from naive thresholding |
| **Scoped RAG chat** | Per-job vector index (extracted strings + findings); LLM answers grounded only in that job's retrieved context | Prevents hallucinated findings about a specific firmware; hard part is per-job index lifecycle |
| **Executive summary generation** | LLM converts already-computed structured findings into readable prose | AI writes the sentence, never decides the verdict |

---

## 8. NVD API vs. Local CVE Database — Decision and Rationale

**Question raised:** Why maintain a local CVE database instead of calling the NVD API live?

**Decision: Hybrid — bulk-download offline, query locally at runtime.**

Reasons the pure live-API approach was rejected:

1. **Rate limits break the fan-out architecture.** NVD's public API allows a small number of requests per 30 seconds (more with an API key, but still limited). A single firmware blob can fan out into dozens of sub-components needing lookups, across many concurrent jobs — this would require building rate-limiting infrastructure just to protect a third-party dependency.
2. **Latency compounds across fan-out.** A local pgvector similarity search is single-digit milliseconds; an external HTTP call per sub-component, multiplied across a wide fan-out, turns a fast job into one gated by third-party network round-trips.
3. **NVD API does exact/structured matching (via CPE strings), not fuzzy matching** — and fuzzy matching is the actual value-add. Real extracted version strings are messy (`BusyBox v1.31.1 (2020-05-08 ...)`, `busybox_1.31.1-r2`, truncated/corrupted strings). The API doesn't solve this normalization problem — you still have to build it either way.
4. **No offline/air-gapped story with a live API.** Real security tooling often must run without sending details about proprietary client firmware to third parties. "Works with zero external runtime dependencies" is a strong system design point.
5. **Resume-quality mismatch.** "I called the NVD API" is a five-line HTTP call. "I built a local fuzzy-matching retrieval system over the CVE corpus" is the actual system design skill being demonstrated.

**Final hybrid design:**
1. Bulk-download the NVD CVE **data feed** once, offline (NVD publishes feeds specifically to avoid live API hammering).
2. Parse and embed the corpus into pgvector locally — a one-time/periodic ETL job, not a runtime dependency.
3. **Nightly APScheduler job (runs in the router process)** pulls the incremental feed and re-embeds new/changed CVEs — self-updating index, worth mentioning as a feature.
4. **Runtime path never touches the internet** — pure local similarity search, fast and reliable.

---

## 9. Building the CVE Query / CPE Strings (the actual hard part)

**Step 1 — Extract raw candidate strings** from binaries during static analysis (e.g. `BusyBox v1.31.1 (2020-05-08 12:31:12 UTC)`, `OpenSSL 1.0.2k-fips`, `libcurl/7.29.0`).

**Step 2 — Normalize via regex patterns per known component family.** Maintain a small library covering common embedded components (BusyBox, OpenSSL, libcurl, Dropbear, uClibc, Linux kernel strings, etc. — a few dozen patterns covers most real-world firmware):
```python
patterns = {
    "busybox": r"BusyBox\s+v?(\d+\.\d+\.\d+)",
    "openssl": r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)",
    "libcurl": r"libcurl/(\d+\.\d+\.\d+)",
}
```
This yields `(vendor, product, version)` tuples.

**Step 3 — Construct a well-formed CPE string:**
```
cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
```

**Step 4 — Handle cases regex can't resolve (where embeddings earn their place):**
- Embed the raw messy string using a small local sentence-transformer model (no API cost).
- Similarity-search against a pre-embedded index of known vendor:product:version combinations from the local CVE corpus.
- Take top-k nearest matches as candidates; only auto-confirm above a confidence threshold, otherwise flag for review.

**Step 5 — Lookup order:** exact CPE match first, falling back to embedding similarity on CVE description text if no exact CPE hit exists (handles cases where vendors mislabel their own CPE identifiers).

**Core insight:** there's no clean API for "fuzzy-match this garbled string extracted from a binary into a real product identifier." This normalization-then-retrieval pipeline is the genuine, nontrivial engineering problem — solving it locally is a stronger portfolio story than calling an endpoint.

---

## 10. Precision/Recall Trade-off: Bias Toward Recall

**Decision:** Accept more false positives rather than risk false negatives ("no vulnerabilities found" when there actually are).

**Rationale:** In vulnerability scanning the costs are asymmetric —
- False positive: costs an analyst a few minutes to review and dismiss.
- False negative: a device ships with a real vulnerability that goes undetected until exploited.

This mirrors standard practice in security tooling (AV, SAST/DAST, WAFs) — alert and let a human dismiss, rather than stay silent to avoid false alarms.

### Implementation: Confidence Tiers (not a single threshold)

```python
def classify_match(similarity_score, exact_cpe_match):
    if exact_cpe_match:
        return "CONFIRMED"          # exact CPE hit — no ambiguity
    elif similarity_score >= 0.90:
        return "HIGH_CONFIDENCE"    # near-certain fuzzy match
    elif similarity_score >= 0.70:
        return "POSSIBLE"           # worth a human look
    elif similarity_score >= 0.50:
        return "LOW_CONFIDENCE"     # flagged, but clearly marked as noisy
    else:
        return "NO_MATCH"           # below this, even recall-biased, it's just noise
```

**Key caveat — alert fatigue:** simply lowering the threshold without tiering doesn't improve safety; it teaches analysts to ignore the tool. If a scan produces 200 flags and 195 are noise, the human stops reading carefully, making the system *less* safe overall than a well-tuned one producing fewer, higher-signal flags. The real fix is: **lower threshold + tiering + AI-assisted triage**, not threshold-lowering alone.

### AI's Role in Reducing Alert Fatigue
For matches in `POSSIBLE` or `LOW_CONFIDENCE` tiers, feed the retrieved CVE description plus the extracted string context into the LLM to explain *why* it might or might not be a real match (e.g., "the extracted string is truncated at 'busybox 1.3' — could match either 1.31.1 or 1.30.x, recommend manual verification"). Scope this LLM call only to ambiguous tiers — running it on `CONFIRMED` matches wastes cost, running it on `NO_MATCH` is pointless. This scoping decision itself demonstrates cost/latency awareness.

### Feedback Loop for Threshold Calibration
Let analysts mark flagged matches as "confirmed" or "false positive" in the dashboard; log this to Postgres; periodically use it to recalibrate similarity thresholds **per component family** (different components have different version-string messiness and may need different thresholds). This demonstrates managing the precision/recall trade-off dynamically with real feedback, rather than picking one static number forever.

---

## 11. Full-Stack Layer

- **React dashboard:** firmware upload (standard presigned multipart S3 pattern), live job progress via WebSocket (e.g. "14/40 sub-blobs analyzed"), report viewer.
- **Scoped "Ask about this firmware" chat panel:** a RAG chat interface scoped to a single job's report only — not the whole internet. Forces real per-job retrieval infrastructure rather than a generic LLM wrapper.

---

## 12. Low-Level / OS-Network Hook (pick one, prepare deeply)

**Option A — RLIMIT_AS-based subprocess resource capping (unpacker service):**
Explain `RLIMIT_AS`, wall-clock timeouts + SIGKILL, and why OS-level enforcement is required (not just application-level checks) against zip bombs — a bomb can exhaust memory before your Python code even gets a chance to check anything. (cgroups are the ideal enforcement in a real deployment; locally we fall back to `RLIMIT_AS` because in-container cgroup delegation isn't available on unprivileged WSL2 — own that distinction.)

**Option B — Kafka consumer group rebalancing:**
Explain what happens to in-flight messages when a static analysis worker dies mid-processing, how `max.poll.interval.ms` and manual offset commits prevent silent message loss, and why Kafka's at-least-once delivery semantics require every consumer to be **idempotent** — a re-delivered/re-analyzed sub-blob must not double-increment the Redis completion counter. This ties directly back into the architecture's own correctness, which makes it a stronger answer than a memorized fact.

---

## 13. Corner Cases — Development Phase

| Failure Mode | Why It Happens | Fix |
|---|---|---|
| Zip slip / path traversal | Archive entries like `../../etc/cron.d/evil` overwrite files outside the extraction dir | Sanitize every extracted path; reject anything resolving outside the sandboxed root |
| Symlink attacks | Archive contains a symlink pointing to `/etc/passwd`; naive extraction follows it | Disable symlink following, or resolve-and-reject symlinks pointing outside sandbox |
| Recursive archive nesting | Zip-in-zip-in-zip nested very deep, each individually small | Hard cap on recursion depth, independent of size-based zip bomb checks |
| Uncooperative hung subprocess | Corrupted firmware makes extraction tool spin forever; SIGTERM ignored | Hard wall-clock timeout with SIGKILL, plus cgroup memory/CPU caps |
| Non-reproducible extraction | Different tool versions (e.g. binwalk) between laptop and CI produce different sub-blobs | Pin exact tool versions in a container image |
| Encoding chaos in string extraction | Embedded Windows CE binary has UTF-16LE strings; naive ASCII `strings` misses/garbles them | Run multi-encoding extraction explicitly (ASCII + UTF-16LE/BE) |
| Shared temp directory collisions | Two router/extraction workers extract different jobs into the same local temp path | Namespace every extraction path by `job_id`, always |
| Manual Kafka replay during debugging | Resending a test message double-increments the Redis completion counter | Idempotency keys (check-and-set in Redis) before processing, not just before counting |
| Accidentally executing extracted content | Running an extracted binary/script directly "to see what it does" | Hard rule: nothing extracted is ever executed, only statically read |

---

## 14. Corner Cases — Production

| Failure Mode | Why It Happens | Fix |
|---|---|---|
| Poison pill blocking a partition | A malformed message crashes the consumer on every retry; Kafka ordering stalls everything behind it | Catch broad exceptions in the consumer loop; route to DLQ after N failed attempts instead of crash-looping |
| Consumer group rebalance mid-task | Analysis exceeds `max.poll.interval.ms`; Kafka reassigns the partition, message gets redelivered elsewhere | Keep the poll loop responsive — offload slow/CPU-bound work (e.g. binwalk) to a subprocess and keep the consumer thread free to poll, so analysis time never exceeds `max.poll.interval.ms` |
| Fan-out completion race | Aggregator sees `completed == total` prematurely while the unpacker is still discovering new sub-blobs | Use an explicit "extraction complete" marker event, not a bare counter comparison |
| Bloom filter saturation | False-positive rate climbs over months as the filter fills, silently causing new firmware to be skipped as "duplicate" | Capacity-plan filter size upfront, or use a counting/resizable Bloom filter and monitor fill ratio |
| Redis eviction stealing critical state | Structural state shares an instance with LRU-evictable cache data; memory pressure deletes it silently | Isolate structural state (counters, locks, Bloom filter) on a `noeviction` instance/DB |
| Disk exhaustion on unpacker nodes | Failed jobs leave temp extraction files behind because cleanup only ran on the success path | Guaranteed `try/finally` cleanup, plus node-level disk-space circuit breaker |
| S3 multipart partial completion | Job marked `UPLOADED` before multipart upload actually finalizes; downstream consumer 404s | Only emit `firmware.uploaded` after explicit S3 completion callback confirms the object exists |
| Clock skew on TTL locks | Redis lock TTLs computed from local server wall clocks drift across machines | Use Redis's own `TIME` command for TTL math, never local wall-clock time across nodes |
| Noisy-neighbor tenant | One tenant uploads thousands of firmware images, starving everyone else's queue | Per-tenant rate limiting / weighted fair queuing across tenant-partitioned topics |
| Aggregator crash mid-write | Mongo write for a large report partially completes, then the process dies | Idempotent upsert keyed by `job_id`, never append — replay must be safe |
| Cost-based DoS on the AI stage | Attacker uploads firmware purely to drive up embedding/LLM call costs, not to get results | Per-tenant daily quota and a circuit breaker in front of the CVE-matching/LLM stage |
| Secrets sitting in plaintext | Extracted credentials/API keys land unredacted in Mongo reports and logs — leaking the very secrets found | Redact or hash sensitive extracted strings before persistence; encrypt report artifacts at rest |
| Anti-analysis firmware | Some firmware detects static inspection and behaves differently at runtime | Acknowledge explicitly as a known limitation of static analysis (dynamic/QEMU emulation would address it) — stating this unprompted is a strong maturity signal in interviews |

---

## 15. Comparison Context: Firmware Pipeline vs. "Nucleus" (Fleet Dispatch) Idea

When evaluating which project to build first as an undergrad with no prior major systems project:

**Chose firmware pipeline over a Nucleus-style real-time dispatch/geospatial system because:**

1. **Signal density per line of code** — the firmware pipeline's hard parts (Bloom filter dedup, zip bomb defense, DLQ, fan-out/aggregation) are modular and independently demoable; a dispatch system needs geospatial indexing, WebSocket fan-out, distributed locking, and forecasting to all work together for the demo to land, raising execution risk for a solo fresher build.
2. **Rarity** — "design Uber" is the most common system design interview question; a security/firmware analysis pipeline is a far rarer portfolio project.
3. **Fresher credibility** — defensive engineering against adversarial input (zip bombs, malformed binaries) reads as unusually mature for a student project, which typically assumes well-behaved input.
4. **Lower demo/infra cost** — convincing with a handful of real or synthetic malicious firmware samples, vs. needing a live-feeling simulated fleet and historical data to make a dispatch demo credible.

**Where a Nucleus-style project would still win:** if targeting companies with heavy real-time/geospatial systems (ride-share, delivery, logistics, gaming backends) — WebSocket-at-scale and distributed locking under real contention are skills the firmware pipeline doesn't touch. Recommended as a strong **second** project to round out the portfolio after the firmware pipeline.

---

## 16. Other Project Ideas Considered (for portfolio diversification, not built)

1. **Polite Distributed Web Crawler + Semantic Search Engine** — Kafka-partitioned URL frontier, per-domain adaptive rate limiting via Redis Lua-scripted token buckets, Bloom filter URL dedup, embedding-based semantic search over crawled content.
2. **Multi-Tenant API Gateway & Rate-Limiter-as-a-Service** — custom Kong/Cloudflare-lite with per-tenant sliding-window rate limits, custom multi-tenant Postgres indexing (composite tenant_id index vs. schema-per-tenant vs. RLS trade-off), AI-based anomaly detection on traffic patterns.
3. **Real-Time Financial Fraud/Anomaly Detection Engine** — Kafka transaction stream, Redis real-time feature store (rolling velocity checks), embedding-based similarity search against known fraud-ring behavioral patterns.
4. **Real-Time Collaborative Code Intelligence Platform** — CRDT/OT-based concurrent editing, Kafka event-sourced edit history, RAG over the live file's AST/symbol table for contextual code review suggestions.
5. **Visual Content Moderation & Near-Duplicate Detection Pipeline** — perceptual hashing + Redis for near-duplicate detection, CLIP-style embeddings for semantic matching against banned-content vector index.

---

## 17. Local Development Strategy — The "Fat Container" Pattern

### The Problem
Microservices are designed to scale horizontally across a cloud cluster. Cramming 8–10 separate service containers (each with their own OS layer/runtime overhead) onto a single 8–16GB WSL2/Windows machine causes severe memory pressure and can trigger OOM crashes regardless of per-container resource caps. Running a full, unoptimized microservices cluster locally also wrecks developer experience — Docker Desktop/WSL2 can starve the host, freezing the IDE, browser, and frontend dev server.

### The Solution: Logical Microservices via a Physical "Fat Container"
Preserve the distributed, event-driven **logic** (services still communicate only via Kafka/Redpanda topics) while collapsing the **physical** deployment footprint to a single process locally.

**1. The Unified Kafka Event Router (not a "Fat Celery Worker")**

Initial suggestion was a single Celery container subscribed to all Kafka topics. This was corrected: **Celery and Kafka are fundamentally incompatible at the protocol layer.** Celery is built around AMQP and tracks discrete tasks via UUIDs and state (`PENDING`, `SUCCESS`); Kafka is an append-only log tracked via partition offsets and consumer groups. Forcing Celery to consume Kafka topics leads to consumer rebalance storms and dropped offsets.

**Correct implementation:** a single lightweight Python process running a native Kafka consumer (`confluent-kafka` — C-extension backed, fast — or `aiokafka` for async) that polls Redpanda and routes each message to the correct handler function based on topic name:

```python
# consumer_runner.py — the "fat" entrypoint for local dev
TOPIC_HANDLERS = {
    "firmware.uploaded": handle_triage,
    "firmware.triaged": handle_unpack,
    "firmware.extracted": handle_analysis,
    "firmware.analyzed": handle_cve_match,
    "firmware.matched": handle_aggregate,
}
# Local dev: SERVICES=all -> subscribe to every topic in one process
# Production: SERVICES=triage -> subscribe to just firmware.uploaded
```

Celery is dropped entirely — not as the message transport, and not as a task executor either. The CPU-bound, resource-sandboxed extraction work (the `binwalk` subprocess) is launched directly via Python's `subprocess` module from within the handler (with `RLIMIT_AS` + wall-clock timeout + SIGKILL), and the periodic CVE-corpus refresh runs via `APScheduler` in the router process. Kafka/Redpanda is the message transport; there is no separate task queue.

**Poison-pill-safe router loop (manual offset commit):**

```python
while True:
    msg = consumer.poll(1.0)
    if msg is None:
        continue
    try:
        handler = TOPIC_HANDLERS[msg.topic()]
        handler(json.loads(msg.value()))
        consumer.commit(msg)  # manual commit, only after success
    except Exception as e:
        producer.send('firmware.dlq', {'original_topic': msg.topic(), 'payload': msg.value(), 'error': str(e)})
        consumer.commit(msg)  # commit anyway — don't let a bad message stall the partition
```

- `enable.auto.commit=False` is the required setting — auto-commit on a timer can mark an offset committed *before* the handler finishes, so a mid-handler crash silently loses the message instead of allowing safe reprocessing. Manual commit-after-success gives genuine at-least-once delivery, which is exactly why every handler must be idempotent (ties back to Section 13/14's poison-pill and idempotency corner cases).
- Catching exceptions **per message** and routing to `firmware.dlq` prevents one malformed payload from stalling an entire partition forever (the "poison pill" failure mode).

**2. The Unified FastAPI Gateway**
Run the Upload Gateway and CVE Matching Service as a single FastAPI process locally (mount both routers into one app) instead of two separate containers — eliminates redundant API runtime memory overhead alongside heavy extraction binaries like `binwalk`.

**3. Native Frontend Execution**
Run the React/Next.js dashboard natively on the host via `npm run dev` — never inside Docker for local development. Avoids Docker's virtualization tax entirely and gives much faster hot-reloading.

**4. Strict Boundary Discipline (the rule that makes this legitimate, not a shortcut)**
Handlers must **never** call each other directly in-process, even though they share memory space locally:

```python
handle_unpack(payload)  # WRONG — creates a real monolith
kafka_producer.send('firmware.triaged', payload)  # RIGHT — event-driven decoupling preserved
```

All inter-stage communication happens only through Kafka topics, regardless of whether producer and consumer currently live in the same fat process. This discipline is what allows the switch from fat-container to fully distributed deployment to require **zero code changes** — only configuration/compose changes.

**5. Path to Production — Docker Compose Profiles**
The fat container pattern doesn't lock the architecture into a monolith:
- **Local dev** (`docker-compose.yml`): one router process, `SERVICES=all`, consuming every topic.
- **Production** (`docker-compose.prod.yml`): four (or more) identical router containers, each passed a different `SERVICES=` value (`triage`, `unpack`, `analysis`, `report`), scaled independently.
- The Python codebase is identical in both cases — only the deployment topology (env vars + compose file) changes.

**Interview framing:** *"To develop locally without virtualization overhead, I built a unified Kafka event router that dynamically subscribes to topics based on environment variables. Locally, one process runs every handler. In production, I run the same code as four independently-scaled containers, each subscribed to only its own topic. The codebase never changes — only the deployment topology."*

### Infrastructure Memory Optimizations for Local Dev

| Component | Risk | Fix |
|---|---|---|
| Kafka broker | Real Apache Kafka + Zookeeper has heavy JVM overhead (multi-GB) | Use **Redpanda** — Kafka-API-compatible, single Go binary, thread-per-core architecture, ~300–500MB footprint |
| MongoDB | WiredTiger storage engine defaults to reserving ~50% of available RAM (minus 1GB) — can silently consume gigabytes and starve other containers under a constrained WSL2 budget | Cap explicitly: `--wiredTigerCacheSizeGB 0.5` in the Docker Compose command |
| S3 | Real AWS S3 has no local equivalent | Use **MinIO** — lightweight single-binary local S3-compatible storage |
| WSL2 host overall | Docker Desktop/WSL2 can consume 10–12GB, starving the Windows host (IDE, browser, frontend dev server start freezing) | Cap WSL2 via `.wslconfig` (e.g. 6–8GB limit) |
| Per-container limits | Relying on the WSL2-wide cap alone lets one runaway container starve the others inside that shared budget | Set explicit `mem_limit` per service in `docker-compose.yml` (Postgres, Mongo, Redpanda, router process each capped individually) |

### Debugging Benefit
With four logically-separate stages running in one process locally, there is a single unified terminal log stream for the entire backend worker layer — a message's full journey (triage → unpack → analysis → report) is visible in one place, instead of tailing four separate container logs during development.

### Suggested Build Sequencing
1. Get Redpanda + the pure Python router skeleton working against a dummy topic first (produce a test event, confirm routing, log it) — validate the plumbing before adding firmware-specific logic.
2. Wire in the real topic chain one stage at a time (`uploaded → triaged → extracted → analyzed → matched → completed`), testing each hop in isolation with a manually-produced test message before connecting the next stage.
3. Only after the full chain works end-to-end in fat-container mode, add the `SERVICES=` environment variable split and the production Compose file — this is a configuration change at the end, not something to design around from day one.

### Execution Tip: The WSL2 Virtual Disk Trap

During local testing, hundreds of dummy firmware files will get uploaded repeatedly to exercise the extraction/fan-out logic. Left unmanaged, this silently fills up the host disk.

**Root cause (two layers, both must be handled):**
1. **Accumulating test objects** — raw uploads and extracted sub-blobs pile up in MinIO with no expiry, growing without bound over a multi-week build.
2. **WSL2 virtual disk never shrinks automatically** — WSL2 stores its entire filesystem in a virtual hard disk file (`ext4.vhdx`). Even after deleting files from inside MinIO/Linux (`rm`, or an expired lifecycle policy), Windows does **not** automatically reclaim that space on the `C:\`/`D:\` host drive — the `.vhdx` file holds onto its allocated size permanently until manually compacted.

**Required fix — both parts:**
- **MinIO bucket lifecycle policy**: create a dedicated `raw-uploads` bucket and configure automatic object expiration (e.g. 24 hours) so test data doesn't accumulate indefinitely inside the filesystem in the first place.
- **Periodic manual `.vhdx` compaction**: even with the lifecycle policy freeing space *inside* the Linux filesystem, the Windows-side virtual disk file itself still needs periodic compaction (via PowerShell `diskpart` / `Optimize-VHD`) to actually shrink on disk — deleting files alone does not return that space to the host drive.

Skipping either step results in the same symptom: the Windows host drive silently fills up over the course of the build despite the developer believing test data was already cleaned up.

---

## 18. Additional Analysis Modules & RBAC Tiering (Inspired by Azure Firmware Analysis Service)

Reference: Microsoft's production Azure Firmware Analysis service was reviewed for what a "real" firmware analysis product covers beyond CVE matching. It provides: a software bill of materials (SBOM), CVE analysis, binary hardening analysis (compiler security flags), SSL certificate analysis, public/private key analysis, and password hash extraction. The following were selected as low-complexity, high-signal additions — each reuses data already computed by the existing pipeline rather than introducing new architectural components.

### 18.1 Hardcoded Secret / Key Detection
Extends the existing string-extraction stage (already run for CVE version-string matching) with an additional pattern-matching pass over the same extracted strings:
- Private key headers (e.g. `-----BEGIN RSA PRIVATE KEY-----`)
- Common hardcoded credential patterns (`password=`, default admin credentials, API key formats)

**Why low-cost:** reuses the existing string-extraction output; only adds a second regex library pass in the Static Analysis stage. No new Kafka topics, no new services — just an additional field on the existing `firmware.analyzed` event payload.

### 18.2 Binary Hardening Flags Check
Checks whether extracted binaries were compiled with standard security hardening flags: `NX` (no-execute), `PIE` (position-independent executable), `RELRO` (relocation read-only), and stack canaries.

**Implementation approach:** use an existing open-source tool (e.g. `checksec`) or parse ELF headers directly for these flags. Runs as one additional analysis step consuming already-extracted binaries, emitting a small structured result:
```json
{"nx": true, "pie": false, "relro": "partial", "canary": true}
```
This is appended to the `firmware.analyzed` event payload — no changes to Kafka topology.

### 18.3 Minimal SBOM (Software Bill of Materials) Output
The pipeline already resolves `(vendor, product, version)` tuples internally for CVE matching (see Section 9). This adds near-zero extra work: persist that same resolved list as a structured `sbom.json` artifact alongside the final report (uploaded to S3/MinIO with the rest of the job's output), rather than using it only internally for CVE lookups.

**Why worth doing:** SBOM generation is a recognized supply-chain-security compliance concept (referenced in U.S. Executive Order 14028) and is a stronger resume/interview term than "extracted version strings" alone, despite requiring no new computation.

### 18.4 Explicitly Out of Scope (deliberately skipped for a 30-day solo build)
- **SSL certificate analysis** (expired/revoked cert detection) — requires correctly parsing X.509 certificates out of arbitrary binary blobs; disproportionate parsing effort for a comparatively small security signal versus the three additions above.
- **Binary disassembly/decompilation** beyond string and entropy analysis — this is a distinct skill domain (Ghidra/IDA-scripting-level work) and not proportionate to the project timeline.

### 18.5 Three-Tier RBAC (mirrors Azure's Firmware Analysis Service role hierarchy)
Azure's firmware analysis service scopes access via three roles: an Admin role (can upload/analyze, manage workspace configuration), a User/Analyst role (can upload/analyze, view results, no workspace configuration access), and a Reader role (view/download results only, no upload capability).

**Adopted for this project** as a refinement of a flat admin/user RBAC model into three distinct tiers:
- **Admin** — upload, analyze, manage system configuration (e.g. CVE corpus refresh schedule, confidence-tier thresholds)
- **Analyst** — upload, analyze, view/triage results, provide feedback on match confidence (feeds the recalibration loop in Section 10)
- **Reader** — view and download completed reports only; no upload or triage capability

**Why low-cost:** this is a refinement of standard JWT role-claims logic — no new infrastructure, just an additional role tier and corresponding permission checks at the API layer.

---

## 19. Guiding Principles Established in This Discussion

- **AI is always downstream of a deterministic decision, never upstream of one.**
- **Bias toward recall over precision in security contexts**, but always paired with confidence tiering to avoid alert fatigue.
- **Every defensive layer (zip bomb, path traversal, symlinks) is independent** — no single check is trusted alone.
- **Idempotency is mandatory** everywhere Kafka's at-least-once delivery semantics apply.
- **Structural state and cache state must be isolated in Redis** to prevent eviction-related correctness bugs.
- **Local/offline-first data dependencies** (CVE corpus) are preferred over live third-party API calls where fuzzy matching, latency, and air-gapped operation matter.
- **Acknowledge known limitations explicitly** (e.g., static analysis vs. anti-analysis firmware) rather than overselling the system's guarantees — a stronger signal of engineering maturity than silence.
