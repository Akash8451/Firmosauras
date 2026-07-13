/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The frontend runs NATIVELY on the host (npm run dev), never inside Docker
// (hard-constraints.md). It talks to the gateway (HTTP) and notifier (WebSocket),
// both reachable on localhost because MINIO_SERVER_URL + the broker external
// listeners are host-facing.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: false,
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    css: false,
  },
});
