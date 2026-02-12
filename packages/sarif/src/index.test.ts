import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { mergeSarifRuns } from './index.js';
import type { EngineExecutionMeta, Finding } from '@mergesafe/core';

function mkFinding(engineId: string): Finding {
  return {
    findingId: `${engineId}-f1`,
    title: 'Sample finding',
    severity: 'high',
    confidence: 'high',
    category: 'test',
    owaspMcpTop10: 'MCP-A01',
    engineSources: [{ engineId, engineRuleId: 'RULE1', engineSeverity: 'high', message: 'Sample' }],
    locations: [{ filePath: 'src/test.ts', line: 10, column: 1 }],
    evidence: { excerpt: 'const token = "abc"', note: 'test' },
    remediation: 'Fix it',
    references: [],
    tags: [],
    fingerprint: `${engineId}-fingerprint`,
  };
}

describe('mergeSarifRuns', () => {
  test('writes single merged sarif run for canonical findings', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-merge-'));
    const engineSarifPath = path.join(outDir, 'semgrep.sarif');
    fs.writeFileSync(
      engineSarifPath,
      JSON.stringify({
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'Semgrep' } }, results: [{ ruleId: 'SG1', level: 'warning', message: { text: 'from semgrep' } }] }],
      })
    );

    const enginesMeta: EngineExecutionMeta[] = [
      { engineId: 'mergesafe', displayName: 'MergeSafe', version: 'builtin', status: 'ok', durationMs: 10 },
      { engineId: 'semgrep', displayName: 'Semgrep', version: '1.0', status: 'ok', durationMs: 10, artifacts: { sarif: engineSarifPath } },
    ];

    const merged = mergeSarifRuns({
      outDir,
      enginesMeta,
      canonicalFindings: [mkFinding('mergesafe')],
      redact: true,
    });

    expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);
    expect(Array.isArray(merged.runs)).toBe(true);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0]?.tool.driver.name).toBe('MergeSafe');
  });
});
