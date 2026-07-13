// Runtime endpoints. Defaults match the host-facing ports the compose stack and
// the Task 15 integration entrypoints expose; override via a `.env.local`.

function env(name: string, fallback: string): string {
  const v = (import.meta as { env?: Record<string, string | undefined> }).env?.[name];
  return v && v.length > 0 ? v : fallback;
}

export const GATEWAY_URL = env("VITE_GATEWAY_URL", "http://localhost:8000").replace(/\/$/, "");
export const NOTIFIER_WS_URL = env("VITE_NOTIFIER_WS_URL", "ws://localhost:8001").replace(/\/$/, "");
