import { useCallback, useEffect, useState } from "react";
import { useSession } from "../auth/session";
import { canManageConfig } from "../auth/rbac";
import { getThresholds, recalibrate, type FamilyThreshold } from "../api/client";

// Admin-only configuration management: view per-family confidence-tier thresholds
// and trigger the Task 14 feedback-loop recalibration. Rendered only for a role
// with `manage_config` (admin) — analyst/reader never see it.
export function ConfigPanel() {
  const { role, token } = useSession();
  const [rows, setRows] = useState<FamilyThreshold[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setRows(await getThresholds(token));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [token]);

  useEffect(() => {
    if (canManageConfig(role)) void load();
  }, [role, load]);

  if (!canManageConfig(role)) return null;

  async function onRecalibrate() {
    setBusy(true);
    setNote(null);
    try {
      const res = await recalibrate(token);
      setRows(res.thresholds);
      setNote(
        res.updated.length > 0
          ? `recalibrated: ${res.updated.join(", ")}`
          : "no families had enough feedback to adjust",
      );
    } catch (err) {
      setNote(`error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-label="config management">
      <div className="panel-head">
        <h2>Configuration (admin)</h2>
        <button type="button" onClick={() => void onRecalibrate()} disabled={busy}>
          {busy ? "Recalibrating…" : "Recalibrate thresholds"}
        </button>
      </div>
      {note && (
        <p className="muted" data-testid="recalibrate-note">
          {note}
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <table className="thresholds">
        <thead>
          <tr>
            <th>family</th>
            <th>high</th>
            <th>possible</th>
            <th>low</th>
            <th>source</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.family}>
              <td>{t.family}</td>
              <td>{t.high_confidence.toFixed(2)}</td>
              <td>{t.possible.toFixed(2)}</td>
              <td>{t.low_confidence.toFixed(2)}</td>
              <td>{t.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
