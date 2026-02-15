import { describe, expect, test } from 'vitest';
import {
  AVAILABLE_ENGINES,
  DEFAULT_ENGINES,
  computeScanStatus,
  deriveScanStatus,
  toFinding,
  type RawFinding,
} from './index.js';

describe('engine constants', () => {
  test('DEFAULT_ENGINES remains the canonical default engine set', () => {
    expect(DEFAULT_ENGINES).toEqual(['mergesafe', 'semgrep', 'gitleaks', 'cisco', 'osv']);
  });

  test('DEFAULT_ENGINES is a subset of AVAILABLE_ENGINES', () => {
    for (const engine of DEFAULT_ENGINES) {
      expect(AVAILABLE_ENGINES).toContain(engine);
    }
  });
});

describe('scanStatus computation', () => {
  test('all success -> OK', () => {
    const out = computeScanStatus(['ok', 'ok']);
    expect(out.scanStatus).toBe('OK');
    expect(out.counts).toEqual({ selected: 2, succeeded: 2, nonSuccess: 0 });
  });

  test('mix success and non-success -> PARTIAL', () => {
    const out = computeScanStatus(['ok', 'failed', 'timeout', 'skipped', 'preflight-failed']);
    expect(out.scanStatus).toBe('PARTIAL');
    expect(out.counts).toEqual({ selected: 5, succeeded: 1, nonSuccess: 4 });
  });

  test('all non-success -> FAILED', () => {
    const out = computeScanStatus(['failed', 'timeout', 'skipped', 'preflight-failed']);
    expect(out.scanStatus).toBe('FAILED');
    expect(out.counts).toEqual({ selected: 4, succeeded: 0, nonSuccess: 4 });
  });

  test('hard error forces FAILED', () => {
    const out = computeScanStatus(['ok', 'ok'], { hardError: true });
    expect(out.scanStatus).toBe('FAILED');
  });

  test('deriveScanStatus maps from engine meta', () => {
    expect(
      deriveScanStatus([
        { engineId: 'a', displayName: 'A', version: '1', status: 'ok', durationMs: 1 },
        { engineId: 'b', displayName: 'B', version: '1', status: 'failed', durationMs: 1 },
      ])
    ).toBe('PARTIAL');
  });
});


describe('deterministic evidence payload mapping', () => {
  test('toFinding preserves structured evidence payload', () => {
    const raw: RawFinding = {
      ruleId: 'MS002',
      title: 'Command execution from user-controlled input',
      severity: 'critical',
      confidence: 'medium',
      category: 'injection',
      owaspMcpTop10: 'MCP-A03',
      filePath: 'src/index.ts',
      line: 12,
      evidence: 'exec(req.query.cmd)',
      evidencePayload: {
        ruleId: 'MS002',
        matchType: 'taint',
        matchSummary: 'source=user_input -> sink=exec',
        locations: [{ filePath: 'src/index.ts', line: 12, column: 1 }],
      },
      remediation: 'Avoid shell execution',
      references: [],
      tags: ['exec'],
    };

    const finding = toFinding(raw, false, { scanRoot: process.cwd() });
    expect(finding.evidence.ruleId).toBe('MS002');
    expect(finding.evidence.matchType).toBe('taint');
    expect(finding.evidence.matchSummary).toContain('source=user_input');
    expect(finding.evidence.locations?.[0]?.filePath).toBe('src/index.ts');
  });
});
