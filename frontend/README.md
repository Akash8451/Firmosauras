# Firmosaurus frontend

Native React + TypeScript SPA (Vite). It runs **on the host** (`npm run dev`),
never inside Docker (hard-constraints.md) — it talks to the gateway over HTTP and
to the notifier over WebSocket, both reachable on `localhost` because the compose
stack exposes host-facing listeners.

## Run

```bash
cd frontend
npm install
cp .env.example .env.local   # adjust ports only if your backend differs
npm run dev                  # http://localhost:5173
```

Backend prerequisites (from the repo root): `docker compose up` plus the gateway
and notifier processes (see the root README / Task 15 integration section).

## What it does (Task 13)

- **Presigned upload** — `POST /uploads` → `PUT` each part directly to MinIO →
  `POST /uploads/{id}/complete`. The browser uploads bytes straight to storage.
- **Job list** — polls `GET /jobs`; click a job to inspect it.
- **Live progress** — subscribes to the notifier `GET /ws/jobs/{id}` and shows
  "X/N sub-blobs matched" live (coalescing, latest-wins).
- **Report viewer** — color-coded confidence tiers, SBOM components, binary
  hardening flags, and flagged secrets (contents redacted in the UI).
- **RBAC-aware UI** — reader: view only; analyst: + upload/triage/feedback;
  admin: + configuration management. Mirrors the backend permission table; the
  backend remains the real enforcer.
- **Scoped RAG chat** — always shows the `job_id` it is scoped to; cross-job
  isolation is enforced server-side (Task 14).

## Auth

Set `JWT_SECRET` on the backend for a real deployment and paste a signed HS256
token in the header control; its `role` claim drives the UI. In local dev (no
`JWT_SECRET`) the backend is permissive and the role switcher previews each view.

## MinIO CORS note

The browser `PUT`s parts directly to MinIO and reads the `ETag` response header,
so MinIO must allow the host origin and **expose the `ETag` header**. See the
Task 15 integration notes for the exact `mc admin` CORS setup.

## Tests

```bash
npm test          # vitest run
```

Covers: the RBAC table, the presigned upload orchestration, all three role views,
the always-visible chat scope, live-progress rendering, and the report viewer
(tiers + redacted secrets + feedback).
