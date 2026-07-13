import { describe, it, expect } from "vitest";
import {
  can,
  canManageConfig,
  canSubmitFeedback,
  canTriage,
  canUpload,
  canView,
} from "../auth/rbac";
import { roleFromToken } from "../auth/session";

// Mirrors services/cve_matching/security.py _PERMISSIONS exactly (SCHEMA.md §5).
describe("RBAC permission table", () => {
  it("admin has every permission", () => {
    for (const p of ["upload", "analyze", "view", "feedback", "manage_config"] as const) {
      expect(can("admin", p)).toBe(true);
    }
  });

  it("analyst can upload/analyze/view/feedback but NOT manage_config", () => {
    expect(canUpload("analyst")).toBe(true);
    expect(canTriage("analyst")).toBe(true);
    expect(canView("analyst")).toBe(true);
    expect(canSubmitFeedback("analyst")).toBe(true);
    expect(canManageConfig("analyst")).toBe(false);
  });

  it("reader can only view", () => {
    expect(canView("reader")).toBe(true);
    expect(canUpload("reader")).toBe(false);
    expect(canTriage("reader")).toBe(false);
    expect(canSubmitFeedback("reader")).toBe(false);
    expect(canManageConfig("reader")).toBe(false);
  });
});

describe("roleFromToken", () => {
  function jwt(role: string): string {
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "");
    return `${b64({ alg: "HS256" })}.${b64({ sub: "u", role })}.sig`;
  }

  it("extracts a valid role claim", () => {
    expect(roleFromToken(jwt("analyst"))).toBe("analyst");
    expect(roleFromToken(jwt("reader"))).toBe("reader");
  });

  it("returns null for missing/invalid tokens", () => {
    expect(roleFromToken(null)).toBeNull();
    expect(roleFromToken("not-a-jwt")).toBeNull();
    expect(roleFromToken(jwt("superuser"))).toBeNull();
  });
});
