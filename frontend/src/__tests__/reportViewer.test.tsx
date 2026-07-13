import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SessionProvider } from "../auth/session";
import { ReportViewer } from "../components/ReportViewer";
import type { Role, Report } from "../api/types";
import * as client from "../api/client";

vi.mock("../api/client");

const REPORT: Report = {
  job_id: "job-1",
  status: "COMPLETE",
  generated_at: "2026-07-14T00:00:00Z",
  executive_summary: "Two components with known CVEs.",
  summary_stats: { total_findings: 2, by_tier: { CONFIRMED: 1, POSSIBLE: 1 } },
  components: [
    { vendor: "busybox", product: "busybox", version: "1.31.1", source_sub_blob_id: "sb-1" },
  ],
  findings: [
    {
      cve_id: "CVE-2021-1",
      confidence_tier: "CONFIRMED",
      similarity_score: null,
      matched_via: "exact_cpe",
      llm_rationale: null,
      sub_blob_id: "sb-1",
    },
    {
      cve_id: "CVE-2021-2",
      confidence_tier: "POSSIBLE",
      similarity_score: 0.82,
      matched_via: "embedding_similarity",
      llm_rationale: "version string loosely matches",
      sub_blob_id: "sb-1",
    },
  ],
  hardening: { "sb-1": { nx: true, pie: false, relro: "partial", canary: true } },
  secrets: [{ type: "private_key_header", context: "-----BEGIN RSA PRIVATE KEY-----AAAA" }],
};

function renderAs(role: Role) {
  return render(
    <SessionProvider initialRole={role}>
      <ReportViewer jobId="job-1" />
    </SessionProvider>,
  );
}

describe("ReportViewer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(client.getReport).mockResolvedValue(REPORT);
    vi.mocked(client.submitFeedback).mockResolvedValue({ feedback_id: "fb-1", status: "accepted" });
  });

  it("renders tiers, findings, SBOM and hardening", async () => {
    renderAs("analyst");
    expect(await screen.findByTestId("exec-summary")).toHaveTextContent("known CVEs");
    const tiers = screen.getAllByTestId("finding-tier").map((n) => n.textContent);
    expect(tiers).toEqual(["CONFIRMED", "POSSIBLE"]);
    expect(screen.getByText("1.31.1")).toBeInTheDocument();
    expect(screen.getByText("partial")).toBeInTheDocument(); // RELRO
  });

  it("redacts flagged secret contents (never shows the raw secret)", async () => {
    renderAs("analyst");
    await screen.findByTestId("secrets");
    expect(screen.getByText("private_key_header")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN RSA PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.getByText(/\[redacted/)).toBeInTheDocument();
  });

  it("lets an analyst submit false-positive feedback scoped to the job + cve", async () => {
    renderAs("analyst");
    await screen.findByTestId("exec-summary");
    const fpButtons = screen.getAllByRole("button", { name: /false positive/i });
    await userEvent.click(fpButtons[0]);
    await waitFor(() =>
      expect(vi.mocked(client.submitFeedback)).toHaveBeenCalledWith(
        "job-1",
        { cve_id: "CVE-2021-1", verdict: "false_positive" },
        null,
      ),
    );
  });

  it("hides feedback controls from readers", async () => {
    renderAs("reader");
    await screen.findByTestId("exec-summary");
    expect(screen.queryByRole("button", { name: /false positive/i })).not.toBeInTheDocument();
  });
});
