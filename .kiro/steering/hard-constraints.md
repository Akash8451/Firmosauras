---
inclusion: always
---
# Hard Constraints — Firmware Analysis Pipeline (v2)

These rules apply to EVERY agent, on EVERY task, regardless of which track or file is being edited. They are non-negotiable and take priority over any other instruction unless the user explicitly overrides one in the current conversation.

## Operating Environment
- **Host OS:** Windows 11
- **Virtualization:** Docker Desktop via WSL2 integration.
- **Hardware Constraint:** The host machine has exactly 16GB of LPDDR5X RAM. WSL2 is strictly capped at 8GB via a `.wslconfig` file.
- **CRITICAL DIRECTIVE:** The Linux Out-Of-Memory (OOM) killer is the primary enemy. Memory efficiency is prioritized above all else. Do NOT install, configure, or run heavy JVM-based services (e.g., Apache Kafka, Zookeeper).

## Infrastructure Rules (Docker Compose)
1. **Message Broker:** `redpanda` exclusively. Never standard Kafka.
2. **Volumes:** NEVER use bind mounts (`./data:/var/lib/...`) for database or broker data on Windows. Use Docker named volumes only, to prevent WSL2/NTFS cross-OS file corruption.
3. **MinIO Networking:** Must set `MINIO_SERVER_URL=http://localhost:9000` — the frontend runs natively on the host and needs presigned URLs to resolve correctly, not via an internal Docker hostname.
4. **Memory Limits — CRITICAL SYNTAX RULE:** We run plain `docker compose up` (NOT Docker Swarm). `deploy.resources.limits.memory` is silently ignored and provides zero enforcement in this mode. EVERY container MUST use the top-level `mem_limit` key directly (e.g. `mem_limit: 512m`). Never use `deploy:` for resource limits unless explicitly told we're running `docker compose up --compatibility`.
5. **MongoDB Constraint:** Must be started with `--wiredTigerCacheSizeGB 0.5` — its default cache reservation (~50% of available RAM) will otherwise silently starve the rest of the memory budget.
6. **Bucket Lifecycle:** The MinIO `raw-uploads` bucket must have a lifecycle policy auto-expiring objects after 24 hours, to prevent unbounded WSL2 virtual disk (`ext4.vhdx`) growth during repeated local testing. Note: this does not shrink the `.vhdx` file itself — that requires periodic manual PowerShell compaction, a developer-run step, not something to automate in compose.

## Data Source Rules
- **CVE Matching:** Never call the live NVD API at runtime. The CVE corpus is bulk-downloaded from the NVD data feed offline, embedded into local `pgvector`, and refreshed periodically via a scheduled job. Runtime lookups never make an external network call.

## Repo & File Boundary Rules
- The backend is a single "fat container" using the router/handlers layout — NOT one top-level folder per track. Ownership is file-level, not folder-level:
  - `shared/` (contracts, `topics.py`, `redis_keys.py`) — Group 1 owns; other groups import it and may only change it via a flagged, owning-group-reviewed PR.
  - `services/router/runner.py` — Group 1 owns (decorator auto-registration, no shared handler dict to merge-conflict on).
  - `services/router/handlers/{triage,unpack,analysis}.py` — Group 2. `services/router/handlers/{cve_match,aggregate}.py` — Group 3.
  - `services/gateway/` — Group 2 (upload/RBAC) + Group 3 (CVE HTTP surface). `services/notifier/` — Group 3.
  - `frontend/` — Group 4. `scripts/` and `sample_payloads/` — Group 1 seeds; every group adds its own payloads additively.
- Never edit a file your group does not own. Handlers communicate ONLY by producing to the next Kafka topic — never by calling another handler in-process.
- Shared-interface files — `shared/contracts/`, `SCHEMA.md`, `docker-compose.yml`, and the `.kiro/steering/` files — require an explicit flagged PR rather than a silent edit, since every group depends on them.
