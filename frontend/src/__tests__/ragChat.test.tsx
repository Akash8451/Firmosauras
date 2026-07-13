import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SessionProvider } from "../auth/session";
import { RagChatPanel } from "../components/RagChatPanel";
import * as client from "../api/client";

vi.mock("../api/client");

function renderPanel(jobId: string | null) {
  return render(
    <SessionProvider initialRole="analyst">
      <RagChatPanel jobId={jobId} />
    </SessionProvider>,
  );
}

describe("RagChatPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("always shows which job it is scoped to", () => {
    renderPanel("job-A");
    const scope = screen.getByTestId("chat-scope");
    expect(scope).toHaveTextContent("job-A");
  });

  it("shows a different scope for a different job (no cross-job confusion)", () => {
    renderPanel("job-B");
    expect(screen.getByTestId("chat-scope")).toHaveTextContent("job-B");
    expect(screen.getByTestId("chat-scope")).not.toHaveTextContent("job-A");
  });

  it("sends the scoped query and renders the grounded response + sources", async () => {
    vi.mocked(client.cveChat).mockResolvedValue({
      job_id: "job-A",
      answer: "BusyBox 1.31 is affected.",
      grounded: true,
      sources: ["CVE-2021-11111"],
      job_status: "COMPLETE",
    });
    renderPanel("job-A");

    await userEvent.type(screen.getByLabelText("chat question"), "any busybox issues?");
    await userEvent.click(screen.getByRole("button", { name: /ask/i }));

    await waitFor(() =>
      expect(screen.getByText(/BusyBox 1.31 is affected/)).toBeInTheDocument(),
    );
    // The request is scoped to this job_id.
    expect(vi.mocked(client.cveChat).mock.calls[0][0]).toMatchObject({ job_id: "job-A" });
    expect(screen.getByTestId("grounded-flag")).toHaveTextContent(/grounded/i);
    expect(screen.getByText("CVE-2021-11111")).toBeInTheDocument();
  });
});
