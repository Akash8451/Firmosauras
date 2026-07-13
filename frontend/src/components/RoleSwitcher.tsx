import { useSession } from "../auth/session";
import { ROLES } from "../auth/rbac";
import type { Role } from "../api/types";

// Dev affordance: preview each role's view and, optionally, paste a real signed
// token for a deployment with JWT_SECRET set. In local dev (no JWT_SECRET) the
// backend is permissive, so switching the role here changes only the UI surface.
export function RoleSwitcher() {
  const { role, token, setRole, setToken } = useSession();

  return (
    <div className="role-switcher" aria-label="session controls">
      <label>
        Role:{" "}
        <select
          aria-label="role"
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </label>
      <span className="role-badge" data-testid="active-role">
        signed in as {role}
      </span>
      <input
        type="password"
        aria-label="jwt token"
        placeholder="paste signed JWT (optional)"
        value={token ?? ""}
        onChange={(e) => setToken(e.target.value || null)}
      />
    </div>
  );
}
