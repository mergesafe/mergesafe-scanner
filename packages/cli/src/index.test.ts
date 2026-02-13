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
import { defaultAdapters as realDefaultAdapters } from '@mergesafe/engines';
import { DEFAULT_ENGINES } from '@mergesafe/core';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(here, '../../../fixtures/node-unsafe-server');
const repoRoot = path.resolve(here, '../../..');

const UPDATE_GOLDENS = process.env.UPDATE_GOLDENS === '1';

// These tests touch FS + spawn + scan. 5s is flaky on Windows/CI.
const SCAN_TEST_TIMEOUT = 30000;

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

function mkOutDir(prefix = 'mergesafe-test-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/**
 * Golden tests must be stable whether semgrep/gitleaks/osv/cisco/etc are installed.
 * We do that by:
 * - using the real mergesafe adapter
 * - stubbing all other engines to be "unavailable" deterministically
 */
function stubUnavailableAdapter(engineId: string): EngineAdapter {
  const meta = (() => {
    switch (engineId) {
      case 'semgrep':
        return {
          displayName: 'Semgrep (local rules only)',
          installHint: 'Auto-install semgrep into MergeSafe tools cache or install semgrep manually.',
        };
      case 'gitleaks':
        return {
          displayName: 'Gitleaks',
          installHint: 'Auto-install gitleaks into MergeSafe tools cache or install gitleaks manually.',
        };
      case 'osv':
        return {
          displayName: 'OSV-Scanner',
          installHint: 'Auto-install osv-scanner into MergeSafe tools cache or install osv-scanner manually.',
        };
      case 'cisco':
        return {
          displayName: 'Cisco mcp-scanner (offline-safe)',
          installHint:
            'Auto-install cisco-ai-mcp-scanner into MergeSafe tools cache or install it manually (CLI: cisco-ai-mcp-scanner).',
        };
      case 'trivy':
        return {
          displayName: 'Trivy',
          installHint: 'Auto-install trivy into MergeSafe tools cache or install trivy manually.',
        };
      default:
        return {
          displayName: engineId,
          installHint: `Install ${engineId} or enable auto-install.`,
        };
    }
  })();

  return {
    engineId,
    displayName: meta.displayName,
    installHint: meta.installHint,
    async version() {
      return 'unavailable';
    },
    async isAvailable() {
      return false;
    },
    async run() {
      // should never be called because isAvailable=false
      throw new Error('unavailable');
    },
  };
}

function makeDeterministicAdapters(): EngineAdapter[] {
  const mergesafe = realDefaultAdapters.find((a) => a.engineId === 'mergesafe');
  if (!mergesafe) throw new Error('Expected mergesafe adapter to exist in defaultAdapters');

  const stubs = DEFAULT_ENGINES.filter((id) => id !== 'mergesafe').map((id) => stubUnavailableAdapter(id));

  // Ensure one adapter per engineId (no duplicates)
  const seen = new Set<string>();
  const all = [mergesafe, ...stubs].filter((a) => {
    if (seen.has(a.engineId)) return false;
    seen.add(a.engineId);
    return true;
  });

  return all;
}

const deterministicAdapters = makeDeterministicAdapters();

describe('golden scan', () => {
  test(
    'creates report structures and formats',
    async () => {
      const outDir = mkOutDir('mergesafe-test-golden-');
      fs.rmSync(outDir, { recursive: true, force: true });

      const config = {
        outDir,
        format: ['json', 'sarif', 'md', 'html'],
        mode: 'fast' as const,
        timeout: 30,
        concurrency: 4,
        failOn: 'none' as const,
        redact: false,
        autoInstall: false,
        pathMode: 'relative' as const,
        // NOTE: do not set engines here; let it default to DEFAULT_ENGINES
      };

      const result = await runScan(fixture, config, deterministicAdapters);
      const outputPath = writeOutputs(result, config);

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
      expect(md).toMatch(/Scan:\s+\*\*(Completed|Partial)\*\*/);
      expect(md).toContain('Risk grade:');
      expect(md).toContain('Top Findings');
    },
    SCAN_TEST_TIMEOUT
  );

  test(
    'fail-on high returns fail status',
    async () => {
      const outDir = mkOutDir('mergesafe-test-failon-');

      const result = await runScan(
        fixture,
        {
          outDir,
          format: ['json'],
          mode: 'fast',
          timeout: 30,
          concurrency: 4,
          failOn: 'high',
          redact: false,
          autoInstall: false,
          pathMode: 'relative',
        },
        deterministicAdapters
      );

      expect(result.summary.bySeverity.high + result.summary.bySeverity.critical).toBeGreaterThan(0);
      expect(result.summary.status).toBe('FAIL');
    },
    SCAN_TEST_TIMEOUT
  );
});

describe('option parsing utilities', () => {
  test('resolveConfig defaults engines to multi-engine and auto-install on', () => {
    const config = resolveConfig({});
    expect(config.engines).toEqual([...DEFAULT_ENGINES]);
    expect(config.autoInstall).toBe(true);
    expect(config.pathMode).toBe('relative');
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
  test(
    'scan completes and writes outputs when an engine fails',
    async () => {
      const outDir = mkOutDir('mergesafe-test-resilience-');

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
    },
    SCAN_TEST_TIMEOUT
  );
});

function cloneDeep<T>(v: T): T {
  // structuredClone exists on Node 18+; fallback is enough for our JSON objects.
  const sc = (globalThis as any).structuredClone;
  return typeof sc === 'function' ? sc(v) : JSON.parse(JSON.stringify(v));
}

function cmpStr(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function cmpNum(a: number, b: number): number {
  return a - b;
}

const levelRank: Record<string, number> = { error: 1, warning: 2, note: 3 };

function sanitizeReport(input: any): any {
  const clone = cloneDeep(input);
  if (clone.meta) {
    clone.meta.generatedAt = '<redacted-timestamp>';
    clone.meta.engines = (clone.meta.engines ?? []).map((engine: any) => ({ ...engine, durationMs: 0 }));
  }
  return clone;
}

function sanitizeSarif(input: any): any {
  const clone = cloneDeep(input);

  for (const run of clone.runs ?? []) {
    for (const result of run.results ?? []) {
      result.locations = (result.locations ?? [])
        .map((location: any) => {
          const region = location.physicalLocation?.region ?? {};
          return {
            physicalLocation: {
              artifactLocation: {
                uri: String(location.physicalLocation?.artifactLocation?.uri ?? '.').replace(/\\/g, '/'),
              },
              region: {
                startLine: Math.max(1, Number(region.startLine ?? 1)),
                startColumn: Math.max(1, Number(region.startColumn ?? 1)),
                endLine: Math.max(1, Number(region.endLine ?? region.startLine ?? 1)),
                endColumn: Math.max(1, Number(region.endColumn ?? region.startColumn ?? 1)),
              },
            },
          };
        })
        .sort((a: any, b: any) => {
          const aLoc = a.physicalLocation;
          const bLoc = b.physicalLocation;
          const uri = cmpStr(String(aLoc.artifactLocation.uri ?? '.'), String(bLoc.artifactLocation.uri ?? '.'));
          if (uri !== 0) return uri;
          const sl = cmpNum(aLoc.region.startLine, bLoc.region.startLine);
          if (sl !== 0) return sl;
          const sc = cmpNum(aLoc.region.startColumn, bLoc.region.startColumn);
          if (sc !== 0) return sc;
          const el = cmpNum(aLoc.region.endLine, bLoc.region.endLine);
          if (el !== 0) return el;
          return cmpNum(aLoc.region.endColumn, bLoc.region.endColumn);
        });
    }

    run.results = (run.results ?? []).sort((a: any, b: any) => {
      const level = cmpNum(levelRank[a.level] ?? 99, levelRank[b.level] ?? 99);
      if (level !== 0) return level;
      const aP = a.locations?.[0]?.physicalLocation;
      const bP = b.locations?.[0]?.physicalLocation;
      const uri = cmpStr(String(aP?.artifactLocation?.uri ?? '.'), String(bP?.artifactLocation?.uri ?? '.'));
      if (uri !== 0) return uri;
      const line = cmpNum(Number(aP?.region?.startLine ?? 1), Number(bP?.region?.startLine ?? 1));
      if (line !== 0) return line;
      const col = cmpNum(Number(aP?.region?.startColumn ?? 1), Number(bP?.region?.startColumn ?? 1));
      if (col !== 0) return col;
      return cmpStr(String(a.message?.text ?? ''), String(b.message?.text ?? ''));
    });
  }

  return clone;
}

describe('golden deterministic outputs', () => {
  test(
    'matches sanitized json and sarif goldens',
    async () => {
      const goldenDir = path.resolve(repoRoot, 'packages/cli/testdata/goldens/node-unsafe-server');
      const reportGolden = path.join(goldenDir, 'report.json');
      const sarifGolden = path.join(goldenDir, 'results.sarif');

      const tmpOut = mkOutDir('mergesafe-golden-');

      const result = await runScan(
        fixture,
        {
          outDir: tmpOut,
          format: ['json', 'sarif'],
          mode: 'fast',
          timeout: 30,
          concurrency: 4,
          failOn: 'none',
          redact: false,
          autoInstall: false,
          pathMode: 'relative',
          // Important: do NOT specify engines; let defaults apply
        },
        deterministicAdapters
      );

      writeOutputs(result, {
        outDir: tmpOut,
        format: ['json', 'sarif'],
        mode: 'fast',
        timeout: 30,
        concurrency: 4,
        failOn: 'none',
        redact: false,
        autoInstall: false,
        pathMode: 'relative',
      });

      const report = sanitizeReport(JSON.parse(fs.readFileSync(path.join(tmpOut, 'report.json'), 'utf8')));
      const sarif = sanitizeSarif(JSON.parse(fs.readFileSync(path.join(tmpOut, 'results.sarif'), 'utf8')));

      fs.mkdirSync(goldenDir, { recursive: true });
      if (UPDATE_GOLDENS) {
        fs.writeFileSync(reportGolden, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
        fs.writeFileSync(sarifGolden, `${JSON.stringify(sarif, null, 2)}\n`, 'utf8');
      }

      const expectedReport = JSON.parse(fs.readFileSync(reportGolden, 'utf8'));
      const expectedSarif = JSON.parse(fs.readFileSync(sarifGolden, 'utf8'));

      expect(report).toEqual(expectedReport);
      expect(sarif).toEqual(expectedSarif);
    },
    SCAN_TEST_TIMEOUT
  );
});
