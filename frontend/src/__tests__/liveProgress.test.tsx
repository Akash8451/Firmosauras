import { describe, it, expect } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { SessionProvider } from "../auth/session";
import { LiveProgress } from "../components/LiveProgress";
import type { ProgressSnapshot } from "../api/types";

// Minimal fake WebSocket driven by the test to push notifier snapshots.
class FakeWebSocket {
  onopen: (() => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  url: string;
  static last: FakeWebSocket | null = null;
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.last = this;
  }
  open() {
    this.onopen?.();
  }
  push(snapshot: ProgressSnapshot) {
    this.onmessage?.({ data: JSON.stringify(snapshot) } as MessageEvent);
  }
  close() {
    this.onclose?.();
  }
}

describe("LiveProgress", () => {
  it("renders X/N matched from a notifier snapshot and marks the socket open", () => {
    render(
      <SessionProvider initialRole="reader">
        <LiveProgress jobId="job-1" wsFactory={(u) => new FakeWebSocket(u) as unknown as WebSocket} />
      </SessionProvider>,
    );

    const ws = FakeWebSocket.last!;
    expect(ws.url).toContain("/ws/jobs/job-1");

    act(() => ws.open());
    expect(screen.getByTestId("ws-status")).toHaveTextContent("open");

    act(() =>
      ws.push({
        job_id: "job-1",
        stage: "matched",
        status: "in_progress",
        matched: 14,
        total: 40,
        total_final: true,
        progress: "14/40",
        percent: 35,
        counts: { extracted: 40, analyzed: 30, matched: 14 },
      }),
    );

    expect(screen.getByTestId("progress-headline")).toHaveTextContent("14/40 sub-blobs matched");
    expect(screen.getByTestId("progress-stage")).toHaveTextContent("matched");
  });

  it("shows a provisional total (N+) while extraction is still discovering children", () => {
    render(
      <SessionProvider initialRole="reader">
        <LiveProgress jobId="job-2" wsFactory={(u) => new FakeWebSocket(u) as unknown as WebSocket} />
      </SessionProvider>,
    );
    const ws = FakeWebSocket.last!;
    act(() =>
      ws.push({
        job_id: "job-2",
        stage: "extracted",
        status: "in_progress",
        matched: 2,
        total: 5,
        total_final: false,
        progress: "2/5",
        percent: 40,
        counts: { extracted: 5, analyzed: 2, matched: 2 },
      }),
    );
    expect(screen.getByTestId("progress-headline")).toHaveTextContent("2/5+ sub-blobs matched");
  });
});
