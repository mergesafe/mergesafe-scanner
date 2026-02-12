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
    locations: [{ filePath: 'src/test.ts', line: 10 }],
    evidence: { excerpt: 'const token = "abc"', note: 'test' },
    remediation: 'Fix it',
    references: [],
    tags: [],
    fingerprint: `${engineId}-fingerprint`,
  };
}

describe('mergeSarifRuns', () => {
  test('writes single merged run and ensures every result has a valid location', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-merge-'));

    const enginesMeta: EngineExecutionMeta[] = [
      { engineId: 'mergesafe', displayName: 'MergeSafe', version: 'builtin', status: 'ok', durationMs: 10 },
      { engineId: 'cisco', displayName: 'Cisco', version: '1.0', status: 'ok', durationMs: 10 },
    ];

    const findingWithoutLocation: Finding = {
      ...mkFinding('noloc'),
      findingId: 'noloc-f1',
      fingerprint: 'noloc-fingerprint',
      locations: [],
    };

    const findingWithoutLine: Finding = {
      ...mkFinding('noline'),
      findingId: 'noline-f1',
      fingerprint: 'noline-fingerprint',
      locations: [{ filePath: 'src/no-line.ts' }],
    };

    const merged = mergeSarifRuns({
      outDir,
      enginesMeta,
      canonicalFindings: [mkFinding('mergesafe'), findingWithoutLocation, findingWithoutLine],
      redact: true,
    });

    expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);
    expect(Array.isArray(merged.runs)).toBe(true);
    expect(merged.runs.length).toBe(1);
    expect(merged.runs[0].tool.driver.name).toBe('MergeSafe');
    expect(Array.isArray(merged.runs[0].results)).toBe(true);
    expect(merged.runs[0].results.length).toBeGreaterThan(0);

    for (const result of merged.runs[0].results) {
      expect(result.locations).toBeDefined();
      expect(result.locations!.length).toBeGreaterThanOrEqual(1);
      for (const location of result.locations!) {
        const uri = location.physicalLocation?.artifactLocation?.uri;
        expect(typeof uri).toBe('string');
        expect(uri?.trim().length).toBeGreaterThan(0);
      }
    }
  });
});
