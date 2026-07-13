import { useRef, useState } from "react";
import { useSession } from "../auth/session";
import { canUpload } from "../auth/rbac";
import { uploadFirmware } from "../api/client";

// Presigned upload flow. Reader has no `upload` permission, so the control is not
// rendered for them at all (RBAC-aware UI). On success the new job_id is bubbled
// up so the dashboard can select it and start streaming live progress.
export function UploadPanel({ onUploaded }: { onUploaded?: (jobId: string) => void }) {
  const { role, token } = useSession();
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastJob, setLastJob] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  if (!canUpload(role)) {
    // Readers cannot upload — surface why instead of a dead control.
    return (
      <section className="panel" aria-label="upload">
        <h2>Upload firmware</h2>
        <p className="muted" data-testid="upload-denied">
          Your role ({role}) cannot upload firmware. Ask an analyst or admin.
        </p>
      </section>
    );
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setError("choose a firmware file first");
      return;
    }
    setBusy(true);
    setError(null);
    setLastJob(null);
    try {
      const jobId = await uploadFirmware(file, token, setStage);
      setLastJob(jobId);
      onUploaded?.(jobId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
      setStage(null);
    }
  }

  return (
    <section className="panel" aria-label="upload">
      <h2>Upload firmware</h2>
      <form onSubmit={onSubmit}>
        <input ref={fileRef} type="file" aria-label="firmware file" disabled={busy} />
        <button type="submit" disabled={busy}>
          {busy ? "Uploading…" : "Upload"}
        </button>
      </form>
      {stage && <p className="muted">{stage}…</p>}
      {lastJob && (
        <p className="ok" data-testid="upload-ok">
          Submitted job <code>{lastJob}</code>
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
