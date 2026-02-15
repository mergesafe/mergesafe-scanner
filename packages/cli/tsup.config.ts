import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  target: "es2022",
  platform: "node",
  clean: true,
  shims: true,
  sourcemap: true,
  noExternal: [/^@mergesafe\//],
  external: ["yaml", "@babel/parser", "@babel/traverse", "@babel/types"],
  banner: {
    js: "#!/usr/bin/env node",
  },
});
