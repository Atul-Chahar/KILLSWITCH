/// <reference types="vitest" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    // The console is one screen. If the bundle grows past this, something was added
    // that the incident view does not need.
    chunkSizeWarningLimit: 200,
  },
  test: {
    globals: true,
    environment: "node",
  },
});
