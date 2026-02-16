// packages/rules/src/index.test.ts
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runDeterministicRules } from "./index.js";

function byRule(findings: any[], ruleId: string) {
  return findings.filter((f) => f.ruleId === ruleId);
}

function canCreateSymlink(): boolean {
  try {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mergesafe-symlink-"));
    const target = path.join(tmp, "target.js");
    const link = path.join(tmp, "link.js");

    fs.writeFileSync(target, "x\n");
    fs.symlinkSync(target, link);

    // cleanup
    try { fs.unlinkSync(link); } catch {}
    try { fs.unlinkSync(target); } catch {}
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}

    return true;
  } catch (err: any) {
    // Common on Windows without Admin/Developer Mode
    if (err?.code === "EPERM" || err?.code === "EACCES") return false;
    return false;
  }
}

const CAN_CREATE_SYMLINK = canCreateSymlink();

describe("@mergesafe/rules - deterministic taint rules", () => {
  it("flags exactly MS002 + MS003 on node-unsafe-server fixture", () => {
    const fixturePath = path.resolve(__dirname, "../../../fixtures/node-unsafe-server");

    const { findings } = runDeterministicRules(fixturePath, "fast");

    const ms002 = byRule(findings, "MS002");
    const ms003 = byRule(findings, "MS003");

    expect(ms002.length).toBe(1);
    expect(ms003.length).toBe(1);

    const taintOnly = findings.filter((f) => f.ruleId === "MS002" || f.ruleId === "MS003");
    expect(taintOnly.length).toBe(2);

    expect(ms002[0].filePath).toBeTruthy();
    expect(ms002[0].line).toBeGreaterThan(0);
    expect(ms003[0].filePath).toBeTruthy();
    expect(ms003[0].line).toBeGreaterThan(0);
  });

  it("attaches structured evidence payload to deterministic findings", () => {
    const fixturePath = path.resolve(__dirname, "../../../fixtures/node-unsafe-server");
    const { findings } = runDeterministicRules(fixturePath, "fast");

    const deterministic = findings.filter((f) => /^MS\d{3}$/.test(String(f.ruleId ?? "")));
    expect(deterministic.length).toBeGreaterThan(0);

    for (const finding of deterministic) {
      expect(finding.evidencePayload?.ruleId).toBe(finding.ruleId);
      expect(["regex", "taint", "manifest", "heuristic"]).toContain(finding.evidencePayload?.matchType);
      expect((finding.evidencePayload?.matchedSnippet ?? finding.evidencePayload?.matchSummary) || "").toBeTruthy();
      for (const loc of finding.evidencePayload?.locations ?? []) {
        expect(path.isAbsolute(loc.filePath)).toBe(false);
      }
    }
  });

  it.skipIf(!CAN_CREATE_SYMLINK)(
    "skips symlinks and too-large files with deterministic reasons",
    () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mergesafe-rules-"));
      const scanRoot = path.join(tmp, "repo");
      fs.mkdirSync(scanRoot, { recursive: true });

      fs.writeFileSync(path.join(scanRoot, "ok.js"), "console.log('ok')\n");
      fs.writeFileSync(path.join(scanRoot, "big.js"), "x".repeat(2048));

      const linked = path.join(scanRoot, "linked.js");
      fs.symlinkSync(path.join(scanRoot, "ok.js"), linked);

      const { scanStats } = runDeterministicRules(scanRoot, "fast", { maxFileBytes: 1024 });

      expect(scanStats.skipReasons.symlink).toBeGreaterThan(0);
      expect(scanStats.skipReasons.too_large).toBeGreaterThan(0);
      expect(scanStats.filesScanned).toBeGreaterThan(0);
    }
  );
});
