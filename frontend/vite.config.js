import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// In development the UI runs on :5173 and forwards /api to the Python server on :8000.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://localhost:8000" } },
  test: { environment: "jsdom", include: ["src/**/*.ui.test.jsx"], setupFiles: ["./src/test-utils/setup.js"] },
});
