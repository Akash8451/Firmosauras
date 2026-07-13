import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { uploadFirmware } from "../api/client";

// Exercises the client's presigned upload orchestration end-to-end against a
// mocked transport, asserting the EXACT Task 5 three-step sequence and payloads:
//   POST /uploads -> PUT presigned part -> POST /uploads/{id}/complete.

interface Call {
  url: string;
  method: string;
  body?: unknown;
}

function makeRes(body: unknown, init?: { ok?: boolean; status?: number; etag?: string }) {
  return {
    ok: init?.ok ?? true,
    status: init?.status ?? 200,
    statusText: "OK",
    json: async () => body,
    headers: { get: (h: string) => (h.toLowerCase() === "etag" ? init?.etag ?? null : null) },
  } as unknown as Response;
}

describe("uploadFirmware (presigned flow)", () => {
  let calls: Call[];

  beforeEach(() => {
    calls = [];
    const fetchMock = vi.fn(async (url: string, opts?: RequestInit) => {
      const method = opts?.method ?? "GET";
      // Only JSON request bodies are parsed; PUT part bodies are binary blobs.
      const body = typeof opts?.body === "string" ? JSON.parse(opts.body) : undefined;
      calls.push({ url, method, body });

      if (url.endsWith("/uploads") && method === "POST") {
        return makeRes({
          job_id: "job-123",
          s3_key: "raw-uploads/job-123/original.bin",
          upload_id: "up-1",
          parts: [{ part_number: 1, url: "http://localhost:9000/raw-uploads/job-123/original.bin?partNumber=1" }],
        });
      }
      if (method === "PUT") {
        return makeRes(null, { etag: '"etag-abc"' });
      }
      if (url.endsWith("/complete") && method === "POST") {
        return makeRes({ job_id: "job-123", status: "UPLOADED", emitted: true });
      }
      throw new Error(`unexpected request ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("runs create -> PUT part -> complete and returns the job id", async () => {
    const file = new File([new Uint8Array([1, 2, 3, 4])], "fw.bin");
    const stages: string[] = [];

    const jobId = await uploadFirmware(file, "tok", (s) => stages.push(s));

    expect(jobId).toBe("job-123");

    // Three-step sequence, in order.
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toMatch(/\/uploads$/);
    expect(calls[0].body).toMatchObject({ filename: "fw.bin", size_bytes: 4, part_count: 1 });

    expect(calls[1].method).toBe("PUT"); // direct to presigned MinIO URL
    expect(calls[1].url).toContain("localhost:9000");

    expect(calls[2].method).toBe("POST");
    expect(calls[2].url).toMatch(/\/uploads\/job-123\/complete$/);
    expect(calls[2].body).toMatchObject({
      upload_id: "up-1",
      parts: [{ part_number: 1, etag: "etag-abc" }], // quotes stripped
    });

    expect(stages).toContain("submitted");
  });

  it("throws if firmware.uploaded was not emitted", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, opts?: RequestInit) => {
        const method = opts?.method ?? "GET";
        if (url.endsWith("/uploads") && method === "POST") {
          return makeRes({ job_id: "j", s3_key: "k", upload_id: "u", parts: [{ part_number: 1, url: "http://localhost:9000/x" }] });
        }
        if (method === "PUT") return makeRes(null, { etag: "e" });
        return makeRes({ job_id: "j", status: "UPLOADED", emitted: false });
      }),
    );
    const file = new File([new Uint8Array([1])], "fw.bin");
    await expect(uploadFirmware(file, null)).rejects.toThrow(/not emitted/);
  });
});
