import { useEffect, useRef, useState } from "react";
import { NOTIFIER_WS_URL } from "../config";
import type { ProgressSnapshot } from "../api/types";

export type WsStatus = "connecting" | "open" | "closed";

export interface JobProgressState {
  snapshot: ProgressSnapshot | null;
  status: WsStatus;
}

// Subscribe to the notifier WebSocket for one job and expose the latest snapshot.
// The notifier hub is coalescing (latest-wins), so we simply render whatever the
// socket last delivered. `wsFactory` is injectable so tests can drive a fake
// socket without a real notifier process.
export function useJobProgress(
  jobId: string | null,
  token: string | null,
  wsFactory: (url: string) => WebSocket = (url) => new WebSocket(url),
): JobProgressState {
  const [snapshot, setSnapshot] = useState<ProgressSnapshot | null>(null);
  const [status, setStatus] = useState<WsStatus>("closed");
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!jobId) {
      setSnapshot(null);
      setStatus("closed");
      return;
    }

    const qs = token ? `?token=${encodeURIComponent(token)}` : "";
    const url = `${NOTIFIER_WS_URL}/ws/jobs/${encodeURIComponent(jobId)}${qs}`;
    setStatus("connecting");
    setSnapshot(null);

    let ws: WebSocket;
    try {
      ws = wsFactory(url);
    } catch {
      setStatus("closed");
      return;
    }
    socketRef.current = ws;

    ws.onopen = () => setStatus("open");
    ws.onmessage = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data as string) as ProgressSnapshot;
        if (data && data.job_id === jobId) setSnapshot(data);
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onclose = () => setStatus("closed");
    ws.onerror = () => setStatus("closed");

    return () => {
      try {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onclose = null;
        ws.onerror = null;
        ws.close();
      } catch {
        /* already closed */
      }
      socketRef.current = null;
    };
  }, [jobId, token, wsFactory]);

  return { snapshot, status };
}
