import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  target: "es2022",
  clean: true,
  sourcemap: true,
  noExternal: [/^@mergesafe\//],
  skipNodeModulesBundle: true,
  banner: {
    js: "#!/usr/bin/env node",
  },
});
