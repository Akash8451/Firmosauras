import { useSession } from "../auth/session";
import { useJobProgress } from "../hooks/useJobProgress";

// Live "X/N sub-blobs matched" via the notifier WebSocket. `wsFactory` is passed
// through for tests. `total_final=false` means the fan-out total is still
// provisional (extraction not done discovering children), so we show it as such.
export function LiveProgress({
  jobId,
  wsFactory,
}: {
  jobId: string | null;
  wsFactory?: (url: string) => WebSocket;
}) {
  const { token } = useSession();
  const { snapshot, status } = useJobProgress(jobId, token, wsFactory);

  if (!jobId) {
    return (
      <section className="panel" aria-label="progress">
        <h2>Live progress</h2>
        <p className="muted">Select a job to watch its progress.</p>
      </section>
    );
  }

  const matched = snapshot?.matched ?? 0;
  const total = snapshot?.total ?? 0;
  const pct = snapshot?.percent ?? 0;
  const totalLabel = snapshot && !snapshot.total_final ? `${total}+` : `${total}`;

  return (
    <section className="panel" aria-label="progress">
      <div className="panel-head">
        <h2>Live progress</h2>
        <span className={`ws-dot ws-${status}`} data-testid="ws-status" title={`socket ${status}`}>
          {status}
        </span>
      </div>
      {!snapshot ? (
        <p className="muted">Waiting for the first update…</p>
      ) : (
        <div className="progress-block">
          <p className="progress-headline" data-testid="progress-headline">
            {matched}/{totalLabel} sub-blobs matched
          </p>
          <div className="progress-bar" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
            <div className="progress-fill" style={{ width: `${Math.min(pct, 100)}%` }} />
          </div>
          <dl className="progress-stats">
            <div>
              <dt>stage</dt>
              <dd data-testid="progress-stage">{snapshot.stage}</dd>
            </div>
            <div>
              <dt>status</dt>
              <dd data-testid="progress-status">{snapshot.status}</dd>
            </div>
            <div>
              <dt>extracted</dt>
              <dd>{snapshot.counts.extracted}</dd>
            </div>
            <div>
              <dt>analyzed</dt>
              <dd>{snapshot.counts.analyzed}</dd>
            </div>
          </dl>
        </div>
      )}
    </section>
  );
}
