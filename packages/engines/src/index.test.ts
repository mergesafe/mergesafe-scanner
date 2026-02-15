import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { describe, expect, test, vi } from 'vitest';
import { runEngines, type EngineAdapter, existingBinary, verifyFileWithMode } from './index.js';
import { TOOL_MANIFEST } from './toolManifest.js';
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

function sha256(v: string): string {
  return createHash('sha256').update(v).digest('hex');
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

describe('download verification', () => {
  test('checksum OK => installer verification accepts file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-verify-'));
    const file = path.join(dir, 'fixture.bin');
    fs.writeFileSync(file, 'fixture-ok');
    expect(verifyFileWithMode({ mode: 'strict', tool: 'gitleaks', filePath: file, expectedSha256: sha256('fixture-ok') })).toBe(true);
  });

  test('checksum mismatch => strict blocks with explicit error', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-verify-'));
    const file = path.join(dir, 'fixture.bin');
    fs.writeFileSync(file, 'fixture-bad');
    expect(() => verifyFileWithMode({ mode: 'strict', tool: 'gitleaks', filePath: file, expectedSha256: sha256('fixture-ok') })).toThrow(/checksum mismatch/i);
  });

  test('missing checksum: strict blocks, warn logs warning, off ignores', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-verify-'));
    const file = path.join(dir, 'fixture.bin');
    fs.writeFileSync(file, 'fixture-any');

    expect(() => verifyFileWithMode({ mode: 'strict', tool: 'gitleaks', filePath: file })).toThrow(/missing checksum/i);

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    expect(verifyFileWithMode({ mode: 'warn', tool: 'gitleaks', filePath: file })).toBe(true);
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();

    expect(verifyFileWithMode({ mode: 'off', tool: 'gitleaks', filePath: file })).toBe(true);
  });

  test('cached file is verified before use', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-cache-'));
    const oldToolsDir = process.env.MERGESAFE_TOOLS_DIR;
    process.env.MERGESAFE_TOOLS_DIR = tmp;

    try {
      const artifact = TOOL_MANIFEST.gitleaks.artifacts.find((entry) => entry.platform === process.platform && entry.arch === process.arch);
      expect(artifact).toBeTruthy();
      const a = artifact!;

      const target = path.join(tmp, 'bin', 'gitleaks', TOOL_MANIFEST.gitleaks.version, a.binaryName);
      fs.mkdirSync(path.dirname(target), { recursive: true });

      const originalSha = a.sha256;
      fs.writeFileSync(target, 'cached-ok');
      a.sha256 = sha256('cached-ok');
      expect(existingBinary('gitleaks', 'strict')).toBe(target);

      fs.writeFileSync(target, 'cached-tampered');
      expect(() => existingBinary('gitleaks', 'strict')).toThrow(/checksum mismatch/i);
      a.sha256 = originalSha;
    } finally {
      if (oldToolsDir === undefined) delete process.env.MERGESAFE_TOOLS_DIR;
      else process.env.MERGESAFE_TOOLS_DIR = oldToolsDir;
    }
  });
});

describe('external engines smoke (gated)', () => {
  const maybeTest = process.env.RUN_EXTERNAL_ENGINES === '1' ? test : test.skip;
  maybeTest('runs default engines list invocation', async () => {
    const { defaultAdapters } = await import('./index.js');
    expect(defaultAdapters.map((adapter) => adapter.engineId)).toContain('osv');
  });
});
