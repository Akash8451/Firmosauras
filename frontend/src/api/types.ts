// TypeScript mirrors of the REAL backend shapes (SCHEMA.md + services/*).
// These are read straight off the gateway/notifier contracts — not invented.

export type Role = "admin" | "analyst" | "reader";

export type ConfidenceTier =
  | "CONFIRMED"
  | "HIGH_CONFIDENCE"
  | "POSSIBLE"
  | "LOW_CONFIDENCE";

export type MatchedVia = "exact_cpe" | "embedding_similarity";

export type Verdict = "confirmed" | "false_positive" | "needs_review";

// POST /uploads
export interface CreateUploadRequest {
  filename: string;
  size_bytes: number;
  part_count: number;
}

export interface PresignedPart {
  part_number: number;
  url: string;
}

export interface CreateUploadResponse {
  job_id: string;
  s3_key: string;
  upload_id: string;
  parts: PresignedPart[];
}

// POST /uploads/{job_id}/complete
export interface CompletedPart {
  part_number: number;
  etag: string;
}

export interface CompleteUploadResponse {
  job_id: string;
  status: string;
  emitted: boolean;
}

// GET /jobs/{job_id}
export interface JobResponse {
  job_id: string;
  status: string;
  uploaded_by: string;
  created_at: string;
  completed_at: string | null;
}

// POST /cve/chat
export interface ChatResponse {
  job_id: string;
  answer: string | null;
  grounded: boolean;
  sources: string[];
  job_status: string | null;
}

// POST /cve/feedback (and the /jobs/{id}/feedback integration alias)
export interface FeedbackResponse {
  feedback_id: string | null;
  status: string;
}

// WebSocket snapshot from services/notifier/progress.py ProgressTracker.snapshot
export interface ProgressSnapshot {
  job_id: string;
  stage: string;
  status: "in_progress" | "complete" | "error";
  matched: number;
  total: number;
  total_final: boolean;
  progress: string; // "m/n"
  percent: number;
  counts: {
    extracted: number;
    analyzed: number;
    matched: number;
  };
}

// A finding as it appears in the assembled Mongo report doc
// (aggregator.finalize_job -> findings[]).
export interface Finding {
  cve_id: string;
  confidence_tier: ConfidenceTier;
  similarity_score: number | null;
  matched_via: MatchedVia;
  llm_rationale: string | null;
  sub_blob_id: string;
}

export interface SbomComponent {
  vendor: string;
  product: string;
  version: string;
  source_sub_blob_id: string;
}

export interface SecretFlag {
  type: string;
  context: string;
}

export interface HardeningFlags {
  nx: boolean;
  pie: boolean;
  relro: string;
  canary: boolean;
}

// Assembled report (Mongo `reports` doc). `secrets` / `hardening` are optional
// because the frozen report doc keeps findings + components; the Task 15
// integration report endpoint enriches them from firmware.analyzed when present.
export interface Report {
  job_id: string;
  status: string;
  generated_at: string;
  executive_summary: string | null;
  summary_stats: {
    total_findings: number;
    by_tier: Record<string, number>;
  };
  components: SbomComponent[];
  findings: Finding[];
  report_s3_key?: string;
  sbom_s3_key?: string;
  secrets?: SecretFlag[];
  hardening?: Record<string, HardeningFlags>;
}
