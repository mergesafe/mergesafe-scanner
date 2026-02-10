// packages/rules/src/index.test.ts
import { describe, it, expect } from "vitest";
import path from "node:path";
import { runDeterministicRules } from "./index.js";

function byRule(findings: any[], ruleId: string) {
  return findings.filter((f) => f.ruleId === ruleId);
}

describe("@mergesafe/rules - deterministic taint rules", () => {
  it("flags exactly MS002 + MS003 on node-unsafe-server fixture", () => {
    // repoRoot/packages/rules/src -> repoRoot/fixtures/node-unsafe-server
    const fixturePath = path.resolve(__dirname, "../../../fixtures/node-unsafe-server");

    const { findings } = runDeterministicRules(fixturePath, "fast");

    const ms002 = byRule(findings, "MS002");
    const ms003 = byRule(findings, "MS003");

    // PR A expectation: exactly 2 taint findings total (exec + fs write)
    expect(ms002.length).toBe(1);
    expect(ms003.length).toBe(1);

    // Ensure we didn't explode with extra findings from other rules in this fixture
    const taintOnly = findings.filter((f) => f.ruleId === "MS002" || f.ruleId === "MS003");
    expect(taintOnly.length).toBe(2);

    // Basic sanity checks (location present)
    expect(ms002[0].filePath).toBeTruthy();
    expect(ms002[0].line).toBeGreaterThan(0);
    expect(ms003[0].filePath).toBeTruthy();
    expect(ms003[0].line).toBeGreaterThan(0);
  });
});
