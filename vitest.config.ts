/// <reference types="vitest" />
/// <reference types="vite/client" />

import { defineConfig } from "vite";

export default defineConfig({
  test: {
    environment: "edge-runtime",
    setupFiles: ["./vitest.setup.ts"],
    coverage: {
      all: true,
      include: ["src/**/*"],
    },
  },
});
