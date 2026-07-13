import { useCallback, useEffect, useState } from "react";
import { useSession } from "../auth/session";
import { canSubmitFeedback } from "../auth/rbac";
import { getReport, submitFeedback } from "../api/client";
import type { Report, Verdict } from "../api/types";
import { tierColor } from "./tiers";

// Redact a flagged secret's context for display. The backend flags secrets by
// type + a context snippet; we NEVER render the raw snippet in the UI — only the
// type and a masked marker (analysis-modules-rbac.md secret detection).
function redact(context: string): string {
  if (!context) return "[redacted]";
  return `[redacted — ${context.length} chars]`;
}

export function ReportViewer({ jobId }: { jobId: string | null }) {
  const { role, token } = useSession();
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [feedbackNote, setFeedbackNote] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    if (!jobId) return;
    setLoading(true);
    setError(null);
    try {
      setReport(await getReport(jobId, token));
    } catch (err) {
      setReport(null);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [jobId, token]);

  useEffect(() => {
    setReport(null);
    setError(null);
    setFeedbackNote({});
    if (jobId) void load();
  }, [jobId, load]);

  async function sendFeedback(cveId: string, verdict: Verdict) {
    if (!jobId) return;
    try {
      await submitFeedback(jobId, { cve_id: cveId, verdict }, token);
      setFeedbackNote((prev) => ({ ...prev, [cveId]: `recorded: ${verdict}` }));
    } catch (err) {
      setFeedbackNote((prev) => ({
        ...prev,
        [cveId]: `error: ${err instanceof Error ? err.message : String(err)}`,
      }));
    }
  }

  if (!jobId) {
    return (
      <section className="panel" aria-label="report">
        <h2>Report</h2>
        <p className="muted">Select a job to view its report.</p>
      </section>
    );
  }

  return (
    <section className="panel" aria-label="report">
      <div className="panel-head">
        <h2>Report</h2>
        <button type="button" onClick={() => void load()}>
          Reload
        </button>
      </div>

      {loading && <p className="muted">Loading report…</p>}
      {error && (
        <p className="error" role="alert" data-testid="report-error">
          {error}
        </p>
      )}

      {report && (
        <div className="report">
          {report.executive_summary && (
            <p className="exec-summary" data-testid="exec-summary">
              {report.executive_summary}
            </p>
          )}

          <div className="tier-legend" data-testid="tier-summary">
            {Object.entries(report.summary_stats?.by_tier ?? {}).map(([tier, count]) => (
              <span key={tier} className="tier-chip" style={{ backgroundColor: tierColor(tier) }}>
                {tier}: {count}
              </span>
            ))}
          </div>

          <h3>Findings ({report.findings.length})</h3>
          <ul className="findings">
            {report.findings.map((f, i) => (
              <li key={`${f.cve_id}-${f.sub_blob_id}-${i}`} className="finding">
                <div className="finding-head">
                  <span
                    className="tier-chip"
                    style={{ backgroundColor: tierColor(f.confidence_tier) }}
                    data-testid="finding-tier"
                  >
                    {f.confidence_tier}
                  </span>
                  <code>{f.cve_id}</code>
                  <span className="muted">
                    {f.matched_via}
                    {f.similarity_score != null ? ` · ${f.similarity_score.toFixed(2)}` : ""}
                  </span>
                </div>
                {f.llm_rationale && <p className="rationale">{f.llm_rationale}</p>}
                {canSubmitFeedback(role) && (
                  <div className="feedback-actions">
                    <button type="button" onClick={() => void sendFeedback(f.cve_id, "confirmed")}>
                      Confirm
                    </button>
                    <button
                      type="button"
                      onClick={() => void sendFeedback(f.cve_id, "false_positive")}
                    >
                      False positive
                    </button>
                    {feedbackNote[f.cve_id] && (
                      <span className="muted" data-testid={`fb-note-${f.cve_id}`}>
                        {feedbackNote[f.cve_id]}
                      </span>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>

          <h3>SBOM components ({report.components.length})</h3>
          <table className="sbom">
            <thead>
              <tr>
                <th>vendor</th>
                <th>product</th>
                <th>version</th>
              </tr>
            </thead>
            <tbody>
              {report.components.map((c, i) => (
                <tr key={`${c.vendor}-${c.product}-${c.version}-${i}`}>
                  <td>{c.vendor}</td>
                  <td>{c.product}</td>
                  <td>{c.version}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {report.hardening && Object.keys(report.hardening).length > 0 && (
            <>
              <h3>Binary hardening</h3>
              <table className="hardening">
                <thead>
                  <tr>
                    <th>sub-blob</th>
                    <th>NX</th>
                    <th>PIE</th>
                    <th>RELRO</th>
                    <th>canary</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(report.hardening).map(([sb, h]) => (
                    <tr key={sb}>
                      <td>
                        <code>{sb.slice(0, 8)}</code>
                      </td>
                      <td>{h.nx ? "yes" : "no"}</td>
                      <td>{h.pie ? "yes" : "no"}</td>
                      <td>{h.relro}</td>
                      <td>{h.canary ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {report.secrets && report.secrets.length > 0 && (
            <>
              <h3>Flagged secrets (redacted)</h3>
              <ul className="secrets" data-testid="secrets">
                {report.secrets.map((s, i) => (
                  <li key={i}>
                    <span className="secret-type">{s.type}</span>{" "}
                    <span className="muted">{redact(s.context)}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </section>
  );
}
