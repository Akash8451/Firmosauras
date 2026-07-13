import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { SessionProvider } from "../auth/session";
import { Dashboard } from "../components/Dashboard";
import type { Role } from "../api/types";

// Mock the whole client so mounting the dashboard performs no real network I/O.
vi.mock("../api/client", () => ({
  listJobs: vi.fn(async () => []),
  getThresholds: vi.fn(async () => []),
  recalibrate: vi.fn(async () => ({ updated: [], thresholds: [] })),
  getReport: vi.fn(async () => {
    throw new Error("no report");
  }),
  uploadFirmware: vi.fn(),
  cveChat: vi.fn(),
  submitFeedback: vi.fn(),
}));

function renderAs(role: Role) {
  return render(
    <SessionProvider initialRole={role}>
      <Dashboard wsFactory={() => ({ close() {} }) as unknown as WebSocket} />
    </SessionProvider>,
  );
}

describe("RBAC-aware role views", () => {
  beforeEach(() => vi.clearAllMocks());

  it("reader sees no upload control and no config panel", async () => {
    renderAs("reader");
    expect(await screen.findByTestId("upload-denied")).toBeInTheDocument();
    expect(screen.queryByLabelText("firmware file")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("config management")).not.toBeInTheDocument();
    // But readers CAN view: jobs + report + chat panels are present.
    expect(screen.getByLabelText("jobs")).toBeInTheDocument();
    expect(screen.getByLabelText("report")).toBeInTheDocument();
  });

  it("analyst sees upload + feedback but no config panel", () => {
    renderAs("analyst");
    expect(screen.getByLabelText("firmware file")).toBeInTheDocument();
    expect(screen.queryByTestId("upload-denied")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("config management")).not.toBeInTheDocument();
  });

  it("admin sees everything including config management", () => {
    renderAs("admin");
    expect(screen.getByLabelText("firmware file")).toBeInTheDocument();
    expect(screen.getByLabelText("config management")).toBeInTheDocument();
  });
});
