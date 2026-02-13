import { describe, expect, test } from 'vitest';
import { AVAILABLE_ENGINES, DEFAULT_ENGINES, canonicalizeFindingIds, mergeCanonicalFindings, sortFindingsDeterministically, type Finding } from './index.js';

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

describe('deterministic finding identity and ordering', () => {
  test('canonicalizeFindingIds produces machine-independent ids from normalized paths', () => {
    const finding: Finding = {
      findingId: 'tmp',
      title: 'Command execution reachable from tool handlers',
      severity: 'critical',
      confidence: 'high',
      category: 'injection',
      owaspMcpTop10: 'MCP-A10',
      engineSources: [{ engineId: 'mergesafe' }],
      locations: [{ filePath: 'src\\app.js', line: 42 }],
      evidence: { excerpt: 'exec(userInput)', note: 'x' },
      remediation: 'Fix',
      references: [],
      tags: ['Node', 'security', 'node'],
      fingerprint: 'old',
    };

    const [out] = canonicalizeFindingIds([finding]);
    expect(out.findingId).toBe(`ms-${out.fingerprint}`);
    expect(out.locations[0]?.filePath).toBe('src/app.js');
  });

  test('mergeCanonicalFindings evidence picking is deterministic for excerpt/hash ties', () => {
    const mk = (id: string, excerpt?: string, excerptHash?: string): Finding => ({
      findingId: id,
      title: 'Same issue',
      severity: 'high',
      confidence: 'medium',
      category: 'cat',
      owaspMcpTop10: 'MCP-A01',
      engineSources: [{ engineId: 'mergesafe', engineRuleId: 'RULE1' }],
      locations: [{ filePath: 'a.ts', line: 10 }],
      evidence: { excerpt, excerptHash, note: 'n' },
      remediation: 'r',
      references: [],
      tags: [],
      fingerprint: id,
    });

    const [withExcerpt] = mergeCanonicalFindings([
      mk('1', 'bbb'),
      mk('2', 'aaa'),
    ]);
    expect(withExcerpt.evidence.excerpt).toBe('aaa');

    const [withLonger] = mergeCanonicalFindings([
      mk('1', 'short'),
      mk('2', 'much longer evidence'),
    ]);
    expect(withLonger.evidence.excerpt).toBe('much longer evidence');

    const [withHash] = mergeCanonicalFindings([
      mk('1', undefined, 'fff'),
      mk('2', undefined, 'aaa'),
    ]);
    expect(withHash.evidence.excerptHash).toBe('aaa');
  });

  test('sortFindingsDeterministically sorts by severity/path/line/id', () => {
    const findings: Finding[] = [
      {
        findingId: 'ms-b', title: 'b', severity: 'high', confidence: 'low', category: 'c', owaspMcpTop10: 'MCP-A01',
        engineSources: [], locations: [{ filePath: 'b.ts', line: 2 }], evidence: { note: 'n' }, remediation: 'r', references: [], tags: [], fingerprint: 'b',
      },
      {
        findingId: 'ms-a', title: 'a', severity: 'critical', confidence: 'low', category: 'c', owaspMcpTop10: 'MCP-A01',
        engineSources: [], locations: [{ filePath: 'a.ts', line: 1 }], evidence: { note: 'n' }, remediation: 'r', references: [], tags: [], fingerprint: 'a',
      },
    ];

    const sorted = sortFindingsDeterministically(findings);
    expect(sorted.map((f) => f.findingId)).toEqual(['ms-a', 'ms-b']);
  });
});
