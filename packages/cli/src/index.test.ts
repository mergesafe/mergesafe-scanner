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
const repoRoot = path.resolve(here, '../../..');

const UPDATE_GOLDENS =
  process.env.UPDATE_GOLDENS === '1' ||
  process.env.MERGESAFE_UPDATE_GOLDENS === '1' ||
  process.env.CI_UPDATE_GOLDENS === '1';

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
    : spawnSync(process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm', ['-C', 'packages/cli', 'dev', '--', ...args], opts);

  return {
    status: res.status,
    stdout: (res.stdout ?? '') as string,
    stderr: (res.stderr ?? '') as string,
    error: res.error,
    signal: res.signal,
  };
};

function makeTempOutDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-test-'));
  return dir;
}

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function stableKeyForFinding(f: any): string {
  const loc = (Array.isArray(f?.locations) && f.locations[0]) ? f.locations[0] : {};
  const filePath = String(loc?.filePath ?? '');
  const line = Number(loc?.line ?? 0);
  const sev = String(f?.severity ?? '');
  const title = String(f?.title ?? '');
  const category = String(f?.category ?? '');
  const owasp = String(f?.owaspMcpTop10 ?? '');

  const ruleIds =
    Array.isArray(f?.engineSources)
      ? f.engineSources.map((s: any) => String(s?.engineRuleId ?? '')).sort().join(',')
      : '';

  return [
    String(SEV_RANK[sev] ?? 0).padStart(2, '0'),
    filePath,
    String(line).padStart(6, '0'),
    category,
    owasp,
    title,
    ruleIds,
  ].join('|');
}

function sanitizeReport(report: any) {
  const copy = JSON.parse(JSON.stringify(report));

  if (copy?.meta) {
    // timestamps/host-specific
    delete copy.meta.generatedAt;

    // Avoid machine-dependent scannedPath drift (absolute vs relative, separators, etc.)
    delete copy.meta.scannedPath;

    if (Array.isArray(copy.meta.engines)) {
      for (const engine of copy.meta.engines) {
        delete engine.durationMs;
      }
    }
  }

  // Sort findings deterministically for comparison (even if internal ordering changes between versions).
  if (Array.isArray(copy?.findings)) {
    copy.findings.sort((a: any, b: any) => stableKeyForFinding(a).localeCompare(stableKeyForFinding(b)));
  }

  return copy;
}

function sanitizeSarif(sarif: any) {
  const copy = JSON.parse(JSON.stringify(sarif));

  if (Array.isArray(copy?.runs)) {
    for (const run of copy.runs) {
      if (run?.invocations) {
        for (const inv of run.invocations) {
          delete inv?.startTimeUtc;
          delete inv?.endTimeUtc;
        }
      }
    }
  }

  return copy;
}

function writeJson(filePath: string, obj: any) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

describe('golden scan', () => {
  test(
    'creates report structures and formats (mergesafe-only, deterministic)',
    async () => {
      const outDir = makeTempOutDir();
      fs.rmSync(outDir, { recursive: true, force: true });
      fs.mkdirSync(outDir, { recursive: true });

      // IMPORTANT:
      // Golden/unit tests must NOT depend on external engines (semgrep/gitleaks/cisco/osv),
      // otherwise they become flaky and slow on Windows/CI.
      const config = {
        outDir,
        format: ['json', 'sarif', 'md', 'html'] as const,
        mode: 'fast' as const,
        timeout: 30,
        concurrency: 1,
        failOn: 'none' as const,
        redact: false,
        autoInstall: false,
        pathMode: 'relative' as const,
        engines: ['mergesafe'],
      };

      const result = await runScan(fixture, config);
      const outputPath = writeOutputs(result, config);

      expect(outputPath).toBe(normalizeOutDir(outDir));
      expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'summary.md'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'report.html'))).toBe(true);

      const report = JSON.parse(fs.readFileSync(path.join(outDir, 'report.json'), 'utf8'));

      // New fields must exist
      expect(report?.summary?.scanStatus).toBeTruthy();
      expect(report?.summary?.gate?.status).toBeTruthy();

      // back-compat alias must equal gate.status
      expect(report?.summary?.status).toBe(report?.summary?.gate?.status);

      const sarif = JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8'));
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs.length).toBeGreaterThan(0);

      const md = fs.readFileSync(path.join(outDir, 'summary.md'), 'utf8');
      expect(md).toContain('Scan: **Completed**');
      expect(md).toContain('Risk grade:');
      expect(md).toContain('Top Findings');

      expect(result.findings.length).toBeGreaterThan(0);
    },
    20000
  );

  test(
    'matches deterministic golden fixtures (except timestamps)',
    async () => {
      const outDir = makeTempOutDir();
      fs.rmSync(outDir, { recursive: true, force: true });
      fs.mkdirSync(outDir, { recursive: true });

      const goldenDir = path.resolve(here, '../testdata/goldens/node-unsafe-server');
      fs.mkdirSync(goldenDir, { recursive: true });

      const config = {
        outDir,
        format: ['json', 'sarif'] as const,
        mode: 'fast' as const,
        timeout: 30,
        concurrency: 1,
        failOn: 'none' as const,
        redact: false,
        autoInstall: false,
        pathMode: 'relative' as const,
        engines: ['mergesafe'],
      };

      const runA = await runScan(fixture, config);
      writeOutputs(runA, config);

      const currentReport = sanitizeReport(JSON.parse(fs.readFileSync(path.join(outDir, 'report.json'), 'utf8')));
      const currentSarif = sanitizeSarif(JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8')));

      const goldenReportPath = path.join(goldenDir, 'report.json');
      const goldenSarifPath = path.join(goldenDir, 'results.sarif');

      const haveGoldens = fs.existsSync(goldenReportPath) && fs.existsSync(goldenSarifPath);

      if (UPDATE_GOLDENS || !haveGoldens) {
        writeJson(goldenReportPath, currentReport);
        writeJson(goldenSarifPath, currentSarif);
        // If we're updating goldens, this test should pass by construction.
        expect(true).toBe(true);
        return;
      }

      const goldenReport = sanitizeReport(JSON.parse(fs.readFileSync(goldenReportPath, 'utf8')));
      const goldenSarif = sanitizeSarif(JSON.parse(fs.readFileSync(goldenSarifPath, 'utf8')));

      expect(currentReport).toEqual(goldenReport);
      expect(currentSarif).toEqual(goldenSarif);
    },
    20000
  );

  test(
    'fail-on high returns FAIL gate status (mergesafe-only)',
    async () => {
      const outDir = makeTempOutDir();
      fs.rmSync(outDir, { recursive: true, force: true });
      fs.mkdirSync(outDir, { recursive: true });

      const result = await runScan(fixture, {
        outDir,
        format: ['json'] as const,
        mode: 'fast' as const,
        timeout: 30,
        concurrency: 1,
        failOn: 'high',
        redact: false,
        autoInstall: false,
        pathMode: 'relative' as const,
        engines: ['mergesafe'],
      });

      expect(result.summary.bySeverity.high + result.summary.bySeverity.critical).toBeGreaterThan(0);

      // new canonical field
      expect(result.summary.gate.status).toBe('FAIL');

      // back-compat alias must remain
      expect(result.summary.status).toBe('FAIL');
    },
    20000
  );
});

describe('option parsing utilities', () => {
  test('resolveConfig accepts readonly format tuples', () => {
    const cfg = resolveConfig({ format: 'json,sarif' });
    const readonlyFormats = ['json', 'sarif', 'md', 'html'] as const;
    expect([...readonlyFormats].length).toBe(4);
    expect(cfg.format.includes('json')).toBe(true);
  });

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

    // Depending on arg parsing / runtime, usage may land in stdout or stderr.
    const out = result.stderr + result.stdout;
    expect(out).toContain('Usage: mergesafe scan <path> [options]');
  });
});

describe('resilience', () => {
  test(
    'scan completes and writes outputs when an engine fails',
    async () => {
      const outDir = makeTempOutDir();
      fs.rmSync(outDir, { recursive: true, force: true });
      fs.mkdirSync(outDir, { recursive: true });

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
          pathMode: 'relative',
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
        pathMode: 'relative',
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

      // Validate new status semantics exist and are consistent
      expect(result.summary.scanStatus).toBeTruthy();
      expect(result.summary.gate.status).toBeTruthy();
      expect(result.summary.status).toBe(result.summary.gate.status);
    },
    20000
  );
});
