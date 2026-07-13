// RBAC permission table — an EXACT mirror of services/cve_matching/security.py
// _PERMISSIONS (SCHEMA.md §5 / analysis-modules-rbac.md). The backend is the
// real enforcer at the API edge; this table only drives what the UI offers, so a
// reader is never shown an upload control it would be 403'd for anyway.

import type { Role } from "../api/types";

export type Permission =
  | "upload"
  | "analyze"
  | "view"
  | "feedback"
  | "manage_config";

const PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  admin: new Set<Permission>(["upload", "analyze", "view", "feedback", "manage_config"]),
  analyst: new Set<Permission>(["upload", "analyze", "view", "feedback"]),
  reader: new Set<Permission>(["view"]),
};

export const ROLES: Role[] = ["admin", "analyst", "reader"];

export function can(role: Role, permission: Permission): boolean {
  return PERMISSIONS[role]?.has(permission) ?? false;
}

// UI capability helpers, phrased the way the components read.
export const canUpload = (role: Role) => can(role, "upload");
export const canTriage = (role: Role) => can(role, "analyze");
export const canSubmitFeedback = (role: Role) => can(role, "feedback");
export const canManageConfig = (role: Role) => can(role, "manage_config");
export const canView = (role: Role) => can(role, "view");
