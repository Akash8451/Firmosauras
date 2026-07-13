import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { Role } from "../api/types";
import { ROLES } from "./rbac";

// Session model. A real deployment sets JWT_SECRET and the user pastes/receives a
// signed HS256 token whose `role` claim drives both backend enforcement and the
// UI. In local dev the backend is permissive (no JWT_SECRET) and defaults to
// admin, so we mirror that: no token => admin, and a dev role switcher lets you
// preview each of the three role views without minting real tokens.

export interface Session {
  role: Role;
  token: string | null;
  setRole: (role: Role) => void;
  setToken: (token: string | null) => void;
}

function base64UrlDecode(segment: string): string {
  const pad = segment.length % 4 === 0 ? "" : "=".repeat(4 - (segment.length % 4));
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/") + pad;
  // `atob` is available in browsers and in the jsdom test environment.
  return atob(b64);
}

// Best-effort role extraction from an HS256 JWT payload. Signature is NOT
// verified here (the backend does that); we only read the claim to shape the UI.
export function roleFromToken(token: string | null): Role | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(base64UrlDecode(parts[1])) as { role?: string };
    if (claims.role && (ROLES as string[]).includes(claims.role)) {
      return claims.role as Role;
    }
  } catch {
    return null;
  }
  return null;
}

const SessionContext = createContext<Session | null>(null);

export function SessionProvider({
  children,
  initialRole = "admin",
  initialToken = null,
}: {
  children: ReactNode;
  initialRole?: Role;
  initialToken?: string | null;
}) {
  const [token, setTokenState] = useState<string | null>(initialToken);
  // If a token carries a role claim it wins; otherwise use the dev-selected role.
  const [devRole, setDevRole] = useState<Role>(roleFromToken(initialToken) ?? initialRole);

  const setToken = useCallback((next: string | null) => {
    setTokenState(next);
    const claimed = roleFromToken(next);
    if (claimed) setDevRole(claimed);
  }, []);

  const role = roleFromToken(token) ?? devRole;

  const value = useMemo<Session>(
    () => ({ role, token, setRole: setDevRole, setToken }),
    [role, token, setToken],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within a SessionProvider");
  return ctx;
}
