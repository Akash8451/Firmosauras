// HTTP client for the gateway surface. Every shape here matches the REAL backend
// (services/gateway/*, services/cve_matching/*). The presigned upload follows the
// exact three-step Task 5 flow: create -> PUT parts directly to MinIO -> complete.

import { GATEWAY_URL } from "../config";
import type {
  ChatResponse,
  CompleteUploadResponse,
  CompletedPart,
  CreateUploadResponse,
  FeedbackResponse,
  JobResponse,
  Report,
  Verdict,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

function authHeaders(token: string | null): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (body && body.detail != null) return String(body.detail);
  } catch {
    /* non-JSON body */
  }
  return res.statusText || `HTTP ${res.status}`;
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new ApiError(res.status, await readError(res));
  return (await res.json()) as T;
}

// --------------------------------------------------------------------------- //
// Upload flow (POST /uploads -> PUT presigned parts -> POST .../complete).     //
// --------------------------------------------------------------------------- //
export async function createUpload(
  req: { filename: string; size_bytes: number; part_count: number },
  token: string | null,
): Promise<CreateUploadResponse> {
  const res = await fetch(`${GATEWAY_URL}/uploads`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token) },
    body: JSON.stringify(req),
  });
  return json<CreateUploadResponse>(res);
}

// PUT one part's bytes directly to its presigned URL. The presigned URL carries
// its own auth (SigV4), so NO Authorization header is sent here — that would
// break the signature. Returns the ETag MinIO assigns the part.
export async function uploadPart(url: string, body: Blob): Promise<string> {
  const res = await fetch(url, { method: "PUT", body });
  if (!res.ok) throw new ApiError(res.status, `part upload failed: ${res.statusText}`);
  const etag = res.headers.get("ETag") ?? res.headers.get("etag");
  if (!etag) {
    // MinIO must expose ETag via CORS (see the frontend README / Task 15 notes).
    throw new ApiError(
      500,
      "part uploaded but no ETag returned; MinIO CORS must expose the ETag header",
    );
  }
  return etag.replace(/"/g, "");
}

export async function completeUpload(
  jobId: string,
  body: { upload_id: string; parts: CompletedPart[] },
  token: string | null,
): Promise<CompleteUploadResponse> {
  const res = await fetch(`${GATEWAY_URL}/uploads/${encodeURIComponent(jobId)}/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token) },
    body: JSON.stringify(body),
  });
  return json<CompleteUploadResponse>(res);
}

// Orchestrates the whole browser-side upload as a single part (part_count=1):
// a firmware blob is one S3 object. `onStage` surfaces progress to the UI.
export async function uploadFirmware(
  file: File,
  token: string | null,
  onStage?: (stage: string) => void,
): Promise<string> {
  onStage?.("creating upload");
  const created = await createUpload(
    { filename: file.name, size_bytes: file.size, part_count: 1 },
    token,
  );

  onStage?.("uploading to storage");
  const etag = await uploadPart(created.parts[0].url, file);

  onStage?.("finalizing");
  const done = await completeUpload(
    created.job_id,
    { upload_id: created.upload_id, parts: [{ part_number: 1, etag }] },
    token,
  );
  if (!done.emitted) {
    throw new ApiError(409, "upload completed but firmware.uploaded was not emitted");
  }
  onStage?.("submitted");
  return created.job_id;
}

// --------------------------------------------------------------------------- //
// Jobs + report (GET /jobs, GET /jobs/{id}, GET /jobs/{id}/report).            //
// The list + report endpoints are served by the Group 4 integration surface.  //
// --------------------------------------------------------------------------- //
export async function getJob(jobId: string, token: string | null): Promise<JobResponse> {
  const res = await fetch(`${GATEWAY_URL}/jobs/${encodeURIComponent(jobId)}`, {
    headers: authHeaders(token),
  });
  return json<JobResponse>(res);
}

export async function listJobs(token: string | null): Promise<JobResponse[]> {
  const res = await fetch(`${GATEWAY_URL}/jobs`, { headers: authHeaders(token) });
  const body = await json<{ jobs: JobResponse[] }>(res);
  return body.jobs;
}

export async function getReport(jobId: string, token: string | null): Promise<Report> {
  const res = await fetch(`${GATEWAY_URL}/jobs/${encodeURIComponent(jobId)}/report`, {
    headers: authHeaders(token),
  });
  return json<Report>(res);
}

// --------------------------------------------------------------------------- //
// CVE surface (POST /cve/chat, POST /jobs/{id}/feedback).                      //
// --------------------------------------------------------------------------- //
export async function cveChat(
  req: { job_id: string; question: string; top_k?: number },
  token: string | null,
): Promise<ChatResponse> {
  const res = await fetch(`${GATEWAY_URL}/cve/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token) },
    body: JSON.stringify({ top_k: 5, ...req }),
  });
  return json<ChatResponse>(res);
}

// Task 14 contract: POST /jobs/{id}/feedback {cve_id, verdict}. Served by the
// Group 4 integration surface, delegating to the same analyst_feedback store.
export async function submitFeedback(
  jobId: string,
  req: { cve_id: string; verdict: Verdict },
  token: string | null,
): Promise<FeedbackResponse> {
  const res = await fetch(`${GATEWAY_URL}/jobs/${encodeURIComponent(jobId)}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token) },
    body: JSON.stringify(req),
  });
  return json<FeedbackResponse>(res);
}

// --------------------------------------------------------------------------- //
// Config management (admin only — perm `manage_config`). Served by the Group 4  //
// integration surface; drives the Task 14 per-family threshold recalibration.  //
// --------------------------------------------------------------------------- //
export interface FamilyThreshold {
  family: string;
  high_confidence: number;
  possible: number;
  low_confidence: number;
  source: "default" | "recalibrated";
}

export async function getThresholds(token: string | null): Promise<FamilyThreshold[]> {
  const res = await fetch(`${GATEWAY_URL}/config/thresholds`, { headers: authHeaders(token) });
  const body = await json<{ thresholds: FamilyThreshold[] }>(res);
  return body.thresholds;
}

export async function recalibrate(
  token: string | null,
): Promise<{ updated: string[]; thresholds: FamilyThreshold[] }> {
  const res = await fetch(`${GATEWAY_URL}/config/recalibrate`, {
    method: "POST",
    headers: authHeaders(token),
  });
  return json<{ updated: string[]; thresholds: FamilyThreshold[] }>(res);
}
