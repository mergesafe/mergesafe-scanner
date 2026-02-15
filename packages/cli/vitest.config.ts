import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@mergesafe/core': fileURLToPath(new URL('../core/src/index.ts', import.meta.url)),
      '@mergesafe/rules': fileURLToPath(new URL('../rules/src/index.ts', import.meta.url)),
      '@mergesafe/engines': fileURLToPath(new URL('../engines/src/index.ts', import.meta.url)),
      '@mergesafe/report': fileURLToPath(new URL('../report/src/index.ts', import.meta.url)),
      '@mergesafe/sarif': fileURLToPath(new URL('../sarif/src/index.ts', import.meta.url))
    }
  }
});
