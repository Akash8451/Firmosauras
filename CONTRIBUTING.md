# Contributing

This is a compressed (3–4 day) team build split across four groups. The single biggest
failure mode for a project like this is **schema drift** — someone quietly renames a
field and nobody notices until integration day. The whole workflow below exists to
prevent that. Read `TEAM_SPLIT.md` for the full task/ownership map.

## Groups & ownership

Ownership is at the **file level**, not the folder level — the backend is one fat
container, not a folder-per-group split.

| Group | Owns | Branch |
|---|---|---|
| 1 — Foundation | `shared/`, `services/router/runner.py`, `scripts/`, `docker-compose.yml`, `sample_payloads/` seeds, CI gate | merges to `main` first |
| 2 — Ingestion | `services/gateway/` (upload/RBAC), `handlers/{triage,unpack,analysis}.py`, Postgres `jobs` | `group2/ingestion` |
| 3 — Intelligence | `handlers/{cve_match,aggregate}.py`, `services/notifier/`, CVE HTTP surface in `services/gateway/`, CVE ETL | `group3/intelligence` |
| 4 — Surface | `frontend/`, final integration, production profile | `group4/surface` |

**Never edit a file your group does not own.** Handlers communicate ONLY by producing
to the next Kafka topic — never by calling another handler in-process.

## Branching model

- `main` is protected and holds the shared baseline. Merges only via PR with
  owning-group review (CODEOWNERS) + green CI.
- **Group 1 merges to `main` first**; everyone else branches from that baseline.
- `group2/ingestion` and `group3/intelligence` branch from `main` and run in parallel
  against `sample_payloads/` — neither needs the other running.
- `group4/surface` branches only after Groups 2 and 3 merge (it reads their real shapes).
- Use short-lived feature branches off your group branch for individual pieces, e.g.
  `group2/ingestion/zip-bomb-defenses`. Merge to your group branch freely; merge the
  group branch → `main` at agreed sync points.

## Shared-interface files (PR-gated, cross-group review)

These are what everyone depends on. Changing one is a **flagged, narrow-scope PR** with
a reviewer from a *different* group — never a silent local edit:

- `shared/contracts/`, `shared/topics.py`, `shared/redis_keys.py`
- `SCHEMA.md` and the `.kiro/steering/` files
- `docker-compose.yml`
- `services/router/Dockerfile`

If a contract must change (it will, at least once), it's a same-day PR plus a ping to
every affected group, and `SCHEMA.md` + `shared/contracts/` move together in the same
commit. `sample_payloads/` is the executable spec: if a field is ever disputed, the
sample file and the schema are reconciled explicitly via PR.

## CI gate (enforced on every PR)

- **Schema-lint** — every file in `sample_payloads/` must validate against
  `shared/contracts/`.
- **Reviewer checks** —
  - Bloom filter uses `k > 1` distinct bits (not a single-bit hash set).
  - The aggregator gates on `matched_children` (never `completed_children`).
  - No direct handler-to-handler calls — inter-stage communication is Kafka-only.

A handler is not "done" until it has a test that feeds a `sample_payloads/` payload and
asserts the output shape matches the schema (see `backend-architecture.md` rule 7).

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>

feat(triage): add Bloom-filter dedup over Redis bitmap
fix(aggregate): gate on matched_children, not completed_children
docs(schema): pin embedding model to all-MiniLM-L6-v2 (384-dim)
chore(compose): cap MongoDB wiredTigerCacheSizeGB at 0.5
```

- `type` ∈ `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `perf`.
- `scope` is the stage or area (`triage`, `unpack`, `analysis`, `cve_match`,
  `aggregate`, `gateway`, `notifier`, `router`, `shared`, `compose`, `frontend`).
- Keep the summary imperative and under ~70 characters; use the body for the why.
- One logical change per commit. Never commit secrets — `.env` is gitignored;
  `.env.example` ships key names only.

## PR rules

- Keep PRs small and single-purpose; shared-interface PRs especially so (fast review).
- PR description: what changed, what you tested, anything left blocked.
- Never push directly to `main`. Never force-push a shared branch.
- Green CI + required review before merge.

## Async sync

At the end of each work session, post one line to the shared status channel: *which
topic am I producing now, and is its shape still matching `SCHEMA.md`.* That single
habit catches drift the same day instead of on day 4.
