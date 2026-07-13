import { useCallback, useEffect, useState } from "react";
import { useSession } from "../auth/session";
import { listJobs } from "../api/client";
import type { JobResponse } from "../api/types";

// Job list. Polls GET /jobs so new uploads (from any user) appear, and lets the
// operator select a job to inspect. Available to every role (all roles can view).
export function JobList({
  selectedJobId,
  onSelect,
  pollMs = 4000,
}: {
  selectedJobId: string | null;
  onSelect: (jobId: string) => void;
  pollMs?: number;
}) {
  const { token } = useSession();
  const [jobs, setJobs] = useState<JobResponse[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const rows = await listJobs(token);
      setJobs(rows);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [token]);

  useEffect(() => {
    void refresh();
    if (pollMs <= 0) return;
    const id = setInterval(() => void refresh(), pollMs);
    return () => clearInterval(id);
  }, [refresh, pollMs]);

  return (
    <section className="panel" aria-label="jobs">
      <div className="panel-head">
        <h2>Jobs</h2>
        <button type="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {jobs.length === 0 ? (
        <p className="muted">No jobs yet.</p>
      ) : (
        <ul className="job-list">
          {jobs.map((job) => (
            <li key={job.job_id}>
              <button
                type="button"
                className={job.job_id === selectedJobId ? "job selected" : "job"}
                aria-pressed={job.job_id === selectedJobId}
                onClick={() => onSelect(job.job_id)}
              >
                <code>{job.job_id.slice(0, 8)}</code>
                <span className={`status status-${job.status.toLowerCase()}`}>{job.status}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
