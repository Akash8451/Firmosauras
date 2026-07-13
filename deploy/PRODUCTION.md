# Production profile & final integration (Group 4, Task 15)

This is the operator guide for running Firmosaurus as the split-container
production topology, the memory budget under the 8 GB WSL2 cap, the proof that
the split profile is byte-identical to the fat container, and the WSL2 `.vhdx`
compaction runbook.

## Topologies

| Mode | How | Processes |
|---|---|---|
| **Fat container** (dev) | `docker compose up` + host-native `python -m services.router.runner` (`SERVICES=all`) + `uvicorn services.integration.app:app` + `uvicorn services.notifier.app:app` | one router hosts every stage |
| **Split** (prod) | `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build` | four routers (one `SERVICES=` each) + gateway + notifier, all containerized |

The frontend always runs **natively on the host** (`cd frontend && npm run dev`),
never in Docker.

## Byte-identical proof (same code, only compose + env change)

Every application container in `docker-compose.prod.yml` — the four routers, the
gateway, and the notifier — is built from the **one** Group-4 image
`firmosaurus-app:prod` (`deploy/Dockerfile`). They differ ONLY by `command:` and
the `SERVICES` env var. Nothing in `shared/` or `services/` is rebuilt or forked
per stage, so the fat container (`SERVICES=all`) and the split routers run the
exact same bytes.

Confirm it:

```bash
# Build once; all six app services reference the same tag.
docker compose -f docker-compose.yml -f docker-compose.prod.yml build

# One image digest backs every stage.
docker image inspect firmosaurus-app:prod --format '{{.Id}}'

# The fat container is literally the same image with SERVICES=all:
docker run --rm -e SERVICES=all firmosaurus-app:prod python -c "import services.router.runner"
```

The invariants (same image, four routers covering all five stages, `mem_limit`
never `deploy:`, budget < 8 GB) are enforced in CI by
`services/integration/tests/test_prod_profile.py`.

## Memory budget (8 GB WSL2 cap)

`docker compose up` is NOT Swarm, so `deploy.resources.limits` is silently
ignored — every container uses the top-level **`mem_limit`** (hard-constraints.md).
Headroom is parked on the **match router** and the **gateway** because both load
`torch` + the MiniLM embedder (the gateway embeds RAG-chat questions locally).

| Container | `mem_limit` | Measured/expected RSS | Notes |
|---|---:|---:|---|
| redpanda | 700m | ~131 MiB (measured, idle) | broker; `--memory 512M` internal cap |
| mongo | 768m | ~81 MiB (measured, idle) | `--wiredTigerCacheSizeGB 0.5` |
| minio | 512m | ~73 MiB (measured, idle) | object store |
| postgres | 512m | ~21 MiB (measured, idle) | + pgvector |
| redis | 256m | ~10 MiB (measured, idle) | `noeviction`, structural state |
| createbuckets | 128m | 0 (one-shot, exits) | bucket + 24h lifecycle |
| router-triage | 320m | ~120–180 MiB (expected) | sha256 + Bloom |
| router-unpack | 640m | ~150 MiB idle, spikes on extraction (expected) | binwalk subprocess; `RLIMIT_AS` caps children |
| router-analysis | 512m | ~150–250 MiB (expected) | strings + entropy + ELF |
| router-match-aggregate | 1792m | ~700–1100 MiB once torch loads (expected) | **headroom parked here** (torch + MiniLM + pgvector) |
| gateway | 1024m | ~150 MiB, ~500–800 MiB after first RAG chat (expected) | torch loads lazily on `/cve/chat` |
| notifier | 320m | ~120 MiB (expected) | own consumer group |
| **Total `mem_limit`** | **≈ 7.3 GB** | **well under 8 GB** | ~0.7 GB reserved for WSL2/Docker overhead |

The infra RSS figures above are **measured** on this host via `docker stats`
(idle). Confirm the full stack (including the app tier, whose figures are
expected/typical) after warm-up:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
# let the match router load the embedder / process one job, then:
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}"
```

Only the match router and the gateway ever load torch, and rarely at the same
instant, so concurrent RSS in practice sits around 2–2.6 GB — comfortably inside
the cap.

## `.vhdx` compaction runbook (two steps)

Repeated local testing grows the WSL2 virtual disk (`ext4.vhdx`) because deleted
container/volume data isn't returned to the host file automatically.

**Step 1 — reclaim space *inside* the volumes (automated + on demand).**
The MinIO `raw-uploads` bucket has a **24h expiry lifecycle** (configured in
`docker-compose.yml`), so test uploads are purged automatically. To reclaim more
on demand:

```bash
docker system prune -f            # dangling images/containers/networks
docker volume prune -f            # unused named volumes
```

This frees space *inside* the `.vhdx` but does NOT shrink the file itself.

**Step 2 — compact the `.vhdx` (periodic, developer-run PowerShell).**
Shrinking the file is a manual host step:

```powershell
# 1. Stop WSL so the disk is not in use.
wsl --shutdown

# 2a. Preferred (Hyper-V available):
Optimize-VHD -Path "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx" -Mode Full

# 2b. Fallback (Windows Home / no Hyper-V) via diskpart:
#   diskpart
#   select vdisk file="%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx"
#   attach vdisk readonly
#   compact vdisk
#   detach vdisk
#   exit
```

The exact path varies by Docker Desktop version — older builds use
`...\Docker\wsl\data\ext4.vhdx`. This is a periodic developer chore, deliberately
NOT automated in compose.

## No-mock end-to-end run

```bash
# 0. Secrets (once).
cp .env.example .env               # fill JWT_SECRET, LLM_API_KEY, passwords

# 1. Everything, no mocks.
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# 2. Frontend, native on the host.
cd frontend && npm install && npm run dev      # http://localhost:5173
```

Upload a firmware image in the UI and watch it flow
`uploaded → triaged → extracted → analyzed → matched → completed`, with live
"X/N sub-blobs matched" progress from the notifier and the final report
(confidence tiers, SBOM, hardening flags, redacted secrets) in the report viewer.
Replaying a completed job never produces a second report — the aggregator's Mongo
finalize is an atomic `!= COMPLETE → COMPLETE` transition
(`test_integration_app.py::test_replay_completed_job_produces_no_duplicate_report`).
