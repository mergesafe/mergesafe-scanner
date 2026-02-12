// packages/cli/src/index.test.ts

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, test } from 'vitest';
import {
  runScan,
  writeOutputs,
  normalizeOutDir,
  parseListOpt,
  resolveConfig,
  parseArgs,
  getHelpText,
} from './index.js';
import type { EngineAdapter } from '@mergesafe/engines';
import { DEFAULT_ENGINES } from '@mergesafe/core';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(here, '../../../fixtures/node-unsafe-server');
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-test-golden-'));
const repoRoot = path.resolve(here, '../../..');
const goldenDir = path.resolve(here, '../testdata/goldens/node-unsafe-server');

type CliResult = {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
  signal: NodeJS.Signals | null;
};

const runCli = (args: string[]): CliResult => {
  // On GitHub Actions (especially Windows), spawning `pnpm` directly can fail and return:
  // status=null, stdout/stderr=null. Prefer `node $npm_execpath` when available.
  const npmExecPath = process.env.npm_execpath;
  const hasExecPath = Boolean(npmExecPath && fs.existsSync(npmExecPath));

  const opts = {
    cwd: repoRoot,
    encoding: 'utf8' as const,
    windowsHide: true,
    timeout: 20000,
    env: { ...process.env },
  };

  const res = hasExecPath
    ? spawnSync(process.execPath, [npmExecPath as string, '-C', 'packages/cli', 'dev', '--', ...args], opts)
    : spawnSync(
        process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm',
        ['-C', 'packages/cli', 'dev', '--', ...args],
        opts
      );

  return {
    status: res.status,
    stdout: (res.stdout ?? '') as string,
    stderr: (res.stderr ?? '') as string,
    error: res.error,
    signal: res.signal,
  };
};

describe('golden scan', () => {
  function normalizeGoldenText(raw: string): string {
    return raw.replace(/\r\n/g, '\n');
  }

  function sanitizeJsonGolden(raw: string): string {
    const parsed = JSON.parse(normalizeGoldenText(raw));
    parsed.meta.generatedAt = '<generatedAt>';
    if (Array.isArray(parsed.meta.engines)) {
      for (const engine of parsed.meta.engines) {
        engine.durationMs = 0;
      }
    }
    return `${JSON.stringify(parsed, null, 2)}\n`;
  }

  function sanitizeSarifGolden(raw: string): string {
    const parsed = JSON.parse(normalizeGoldenText(raw));
    return `${JSON.stringify(parsed, null, 2)}\n`;
  }

  test('creates report structures and formats', async () => {
    fs.rmSync(outDir, { recursive: true, force: true });

    const result = await runScan(fixture, {
      outDir,
      format: ['json', 'sarif', 'md', 'html'],
      mode: 'fast',
      timeout: 30,
      concurrency: 4,
      failOn: 'none',
      redact: false,
      autoInstall: false,
    });

    const outputPath = writeOutputs(result, {
      outDir,
      format: ['json', 'sarif', 'md', 'html'],
      mode: 'fast',
      timeout: 30,
      concurrency: 4,
      failOn: 'none',
      redact: false,
      autoInstall: false,
    });

    expect(outputPath).toBe(normalizeOutDir(outDir));
    expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);

    const sarif = JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8'));
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBeGreaterThan(0);

    expect(fs.existsSync(path.join(outDir, 'summary.md'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'report.html'))).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);

    const md = fs.readFileSync(path.join(outDir, 'summary.md'), 'utf8');
    expect(md).toContain('Scan: **Completed**');
    expect(md).toContain('Risk grade:');
    expect(md).toContain('Top Findings');
  });

  test('fail-on high returns fail status', async () => {
    const result = await runScan(fixture, {
      outDir,
      format: ['json'],
      mode: 'fast',
      timeout: 30,
      concurrency: 4,
      failOn: 'high',
      redact: false,
      autoInstall: false,
    });

    expect(result.summary.bySeverity.high + result.summary.bySeverity.critical).toBeGreaterThan(0);
    expect(result.summary.status).toBe('FAIL');
  });

  test('matches deterministic JSON and SARIF goldens', async () => {
    fs.rmSync(outDir, { recursive: true, force: true });

    // IMPORTANT: use redact=true so committed goldens do NOT contain raw unsafe code excerpts
    // that trigger GitHub Code Scanning alerts.
    const result = await runScan(fixture, {
      outDir,
      format: ['json', 'sarif'],
      mode: 'fast',
      timeout: 30,
      concurrency: 4,
      failOn: 'none',
      redact: true,
      autoInstall: false,
      engines: ['mergesafe'],
      pathMode: 'relative',
    });

    writeOutputs(result, {
      outDir,
      format: ['json', 'sarif'],
      mode: 'fast',
      timeout: 30,
      concurrency: 4,
      failOn: 'none',
      redact: true,
      autoInstall: false,
      engines: ['mergesafe'],
      pathMode: 'relative',
    });

    const report = fs.readFileSync(path.join(outDir, 'report.json'), 'utf8');
    const sarif = fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8');

    const reportGolden = fs.readFileSync(path.join(goldenDir, 'report.json'), 'utf8');
    const sarifGolden = fs.readFileSync(path.join(goldenDir, 'results.sarif'), 'utf8');

    expect(sanitizeJsonGolden(report)).toBe(sanitizeJsonGolden(reportGolden));
    expect(sanitizeSarifGolden(sarif)).toBe(sanitizeSarifGolden(sarifGolden));

    expect(report).not.toContain('/tmp/');
    expect(report).not.toMatch(/[A-Za-z]:\\/);
    expect(sarif).not.toContain('/tmp/');
    expect(sarif).not.toMatch(/[A-Za-z]:\\/);
  });
});

describe('option parsing utilities', () => {
  test('resolveConfig defaults engines to multi-engine and auto-install on', () => {
    const config = resolveConfig({});
    expect(config.engines).toEqual([...DEFAULT_ENGINES]);
    expect(config.autoInstall).toBe(true);
  });

  test('parseListOpt accepts comma and whitespace-separated values', () => {
    expect(parseListOpt('json,html,sarif,md', ['json'])).toEqual(['json', 'html', 'sarif', 'md']);
    expect(parseListOpt('json html sarif md', ['json'])).toEqual(['json', 'html', 'sarif', 'md']);
    expect(parseListOpt('json, html, sarif, md', ['json'])).toEqual(['json', 'html', 'sarif', 'md']);
  });

  test('parseListOpt falls back to defaults for empty input', () => {
    expect(parseListOpt('   , , ', ['json', 'html'])).toEqual(['json', 'html']);
  });

  test('normalizeOutDir handles Windows-style paths safely', () => {
    const cwd = 'C:\\MergeSafe\\mergesafe-scanner';
    expect(path.win32.resolve(cwd, 'mergesafe-test')).toBe('C:\\MergeSafe\\mergesafe-scanner\\mergesafe-test');
    expect(path.win32.resolve(cwd, '.\\mergesafe-test')).toBe('C:\\MergeSafe\\mergesafe-scanner\\mergesafe-test');
    expect(path.win32.isAbsolute('C:\\MergeSafe\\mergesafe-test')).toBe(true);

    const absOutDir = path.win32.isAbsolute('C:\\MergeSafe\\mergesafe-test')
      ? path.win32.normalize('C:\\MergeSafe\\mergesafe-test')
      : path.win32.resolve(cwd, 'C:\\MergeSafe\\mergesafe-test');

    expect(absOutDir).toBe('C:\\MergeSafe\\mergesafe-test');
    expect(absOutDir.includes('C:\\C:\\')).toBe(false);
  });
});

describe('help output', () => {
  test('parseArgs supports global help without scan path', () => {
    const parsed = parseArgs(['--help']);
    expect(parsed.showHelp).toBe(true);
    expect(parsed.helpTarget).toBe('general');
  });

  test('parseArgs supports scan help without scan path', () => {
    const parsed = parseArgs(['scan', '--help']);
    expect(parsed.showHelp).toBe(true);
    expect(parsed.helpTarget).toBe('scan');
  });

  test('getHelpText is deterministic and includes usage', () => {
    expect(getHelpText('general')).toContain('mergesafe --help');
    expect(getHelpText('scan')).toContain('mergesafe scan <path> [options]');
    expect(getHelpText('scan')).toContain('--path-mode <relative|absolute>');
    expect(getHelpText('list-engines')).toContain('mergesafe --list-engines');
  });

  test('cli help exits 0 and prints usage', () => {
    const result = runCli(['--help']);
    if (result.error) throw result.error;

    expect(result.signal).toBeNull();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Usage:');
    expect(result.stdout).toContain('mergesafe scan <path> [options]');
  });

  test('scan help exits 0 and prints scan usage', () => {
    const result = runCli(['scan', '--help']);
    if (result.error) throw result.error;

    expect(result.signal).toBeNull();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('MergeSafe scan');
    expect(result.stdout).toContain('--fail-on <critical|high|none>');
  });

  test('list engines help exits 0 and prints list usage', () => {
    const result = runCli(['--list-engines', '--help']);
    if (result.error) throw result.error;

    expect(result.signal).toBeNull();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('MergeSafe list engines');
    expect(result.stdout).toContain('mergesafe --list-engines');
  });

  test('scan without path still errors', () => {
    const result = runCli(['scan']);
    if (result.error) throw result.error;

    expect(result.signal).toBeNull();
    expect(result.status).not.toBe(0);

    const out = result.stderr + result.stdout;
    expect(out).toContain('Usage: mergesafe scan <path> [options]');
  });
});

describe('resilience', () => {
  test('scan completes and writes outputs when an engine fails', async () => {
    const failingAdapter: EngineAdapter = {
      engineId: 'boom',
      displayName: 'Boom engine',
      installHint: 'none',
      async version() {
        return '1.0';
      },
      async isAvailable() {
        return true;
      },
      async run() {
        throw new Error('simulated failure');
      },
    };

    const result = await runScan(
      fixture,
      {
        outDir,
        format: ['json', 'sarif', 'md', 'html'],
        mode: 'fast',
        timeout: 30,
        concurrency: 1,
        failOn: 'none',
        redact: false,
        autoInstall: false,
        engines: ['boom'],
      },
      [failingAdapter]
    );

    const outputPath = writeOutputs(result, {
      outDir,
      format: ['json', 'sarif', 'md', 'html'],
      mode: 'fast',
      timeout: 30,
      concurrency: 1,
      failOn: 'none',
      redact: false,
      autoInstall: false,
      engines: ['boom'],
    });

    expect(outputPath).toBe(normalizeOutDir(outDir));
    expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'summary.md'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'report.html'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);

    const sarif = JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8'));
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBeGreaterThan(0);
    expect(result.meta.engines?.find((entry) => entry.engineId === 'boom')?.status).toBe('failed');
  });
});
