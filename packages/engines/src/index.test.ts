import { describe, expect, test, vi } from 'vitest';
import { runEngines, type EngineAdapter } from './index.js';
import type { CliConfig, Finding } from '@mergesafe/core';

const config: CliConfig = {
  outDir: 'tmp',
  format: ['json'],
  mode: 'fast',
  timeout: 1,
  concurrency: 2,
  failOn: 'none',
  redact: false,
  autoInstall: false,
  engines: ['stub-a', 'stub-b', 'stub-timeout'],
};

function mkFinding(engineId: string): Finding {
  return {
    findingId: `${engineId}-1`,
    title: 'Shared finding',
    severity: 'high',
    confidence: 'high',
    category: 'test',
    owaspMcpTop10: 'MCP-A01',
    engineSources: [{ engineId, engineRuleId: 'RULE1', engineSeverity: 'high', message: 'Shared finding' }],
    locations: [{ filePath: '/tmp/file.ts', line: 10 }],
    evidence: { excerpt: 'same-evidence', note: 'test' },
    remediation: 'fix',
    references: [],
    tags: [],
    fingerprint: 'shared-fingerprint',
  };
}

describe('engine runner', () => {
  test('continues when engines fail or timeout and records statuses', async () => {
    const okAdapter: EngineAdapter = {
      engineId: 'stub-a', displayName: 'A', installHint: 'none',
      async version() { return '1.0'; },
      async isAvailable() { return true; },
      async run() { return [mkFinding('stub-a')]; },
    };
    const failAdapter: EngineAdapter = {
      engineId: 'stub-b', displayName: 'B', installHint: 'none',
      async version() { return '1.0'; },
      async isAvailable() { return true; },
      async run() { throw new Error('stub fail'); },
    };
    const timeoutAdapter: EngineAdapter = {
      engineId: 'stub-timeout', displayName: 'T', installHint: 'none',
      async version() { return '1.0'; },
      async isAvailable() { return true; },
      async run() { return new Promise(() => undefined); },
    };

    const result = await runEngines({ scanPath: '.', config }, config.engines!, [okAdapter, failAdapter, timeoutAdapter]);
    expect(result.findings).toHaveLength(1);
    expect(result.meta.find((entry) => entry.engineId === 'stub-a')?.status).toBe('ok');
    expect(result.meta.find((entry) => entry.engineId === 'stub-b')?.status).toBe('failed');
    expect(result.meta.find((entry) => entry.engineId === 'stub-timeout')?.status).toBe('timeout');
  });

  test('dedupes across engines and merges engineSources', async () => {
    const adapterA: EngineAdapter = {
      engineId: 'stub-a', displayName: 'A', installHint: 'none',
      async version() { return '1.0'; },
      async isAvailable() { return true; },
      async run() { return [mkFinding('stub-a')]; },
    };
    const adapterB: EngineAdapter = {
      engineId: 'stub-b', displayName: 'B', installHint: 'none',
      async version() { return '1.0'; },
      async isAvailable() { return true; },
      async run() { return [mkFinding('stub-b')]; },
    };

    const result = await runEngines({ scanPath: '.', config: { ...config, timeout: 2, engines: ['stub-a', 'stub-b'] } }, ['stub-a', 'stub-b'], [adapterA, adapterB]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].engineSources.map((source) => source.engineId).sort()).toEqual(['stub-a', 'stub-b']);
  });
});


describe('binary detection', () => {
  test('uses where.exe on Windows', async () => {
    vi.resetModules();
    const execFileMock = vi.fn((file: string, args: string[], _opts: any, cb: any) => cb(null, 'C:\\Tools\\semgrep.exe\n', ''));
    vi.doMock('node:child_process', () => ({ execFile: execFileMock }));

    const mod = await import('./index.js');
    const platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('win32');
    const ok = await mod.hasBinary('semgrep');

    expect(ok).toBe(true);
    expect(execFileMock).toHaveBeenCalled();
    expect(execFileMock.mock.calls[0][0]).toBe('where.exe');
    platformSpy.mockRestore();
  });
});
