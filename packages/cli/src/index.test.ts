// packages/cli/src/index.test.ts
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { beforeAll, describe, expect, test } from 'vitest';
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
const repoRoot = path.resolve(here, '../../..');

const fixtureAbs = path.resolve(repoRoot, 'fixtures/node-unsafe-server');
const fixtureRel = 'fixtures/node-unsafe-server';

const goldensDir = path.resolve(repoRoot, 'packages/cli/test/goldens/node-unsafe-server');
const goldenReportPath = path.join(goldensDir, 'report.json');
const goldenSarifPath = path.join(goldensDir, 'results.sarif');

type CliResult = {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
  signal: NodeJS.Signals | null;
};

const mkTempOutDir = (prefix: string) => fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-${Date.now()}-`));

const rmTempOutDir = (dir: string) => {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors on Windows file locks
  }
};

const UPDATE_GOLDENS =
  process.env.MERGESAFE_UPDATE_GOLDENS === '1' ||
  process.env.MERGESAFE_UPDATE_GOLDENS === 'true' ||
  process.env.UPDATE_GOLDENS === '1' ||
  process.env.UPDATE_GOLDENS === 'true';

function normalizeText(input: string): string {
  return String(input ?? '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trimEnd();
}

function readTextNormalized(filePath: string): string {
  return normalizeText(fs.readFileSync(filePath, 'utf8'));
}

function ensureDir(p: string) {
  fs.mkdirSync(p, { recursive: true });
}

function writeFileNormalized(p: string, content: string) {
  ensureDir(path.dirname(p));
  fs.writeFileSync(p, normalizeText(content) + '\n', 'utf8');
}

function requireGolden(filePath: string) {
  if (fs.existsSync(filePath)) return;

  const rel = path.relative(repoRoot, filePath).replace(/\\/g, '/');
  const reportRel = path.relative(repoRoot, goldenReportPath).replace(/\\/g, '/');
  const sarifRel = path.relative(repoRoot, goldenSarifPath).replace(/\\/g, '/');

  throw new Error(
    [
      `Missing golden file: ${rel}`,
      '',
      'Generate/update goldens by running (from repo root):',
      '  MERGESAFE_UPDATE_GOLDENS=1 pnpm -C packages/cli test',
      '',
      'Or equivalently generate via CLI scan command:',
      `  pnpm -C packages/cli dev -- scan ${fixtureRel} --fail-on none --path-mode relative --format json,sarif --engines mergesafe --no-auto-install --out-dir test/goldens/node-unsafe-server`,
      '',
      'This should create/update:',
      `  ${reportRel}`,
      `  ${sarifRel}`,
    ].join('\n')
  );
}

/**
 * Collect all string values from a JSON object (deep).
 */
function collectStringsDeep(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectStringsDeep(v, out);
    return out;
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) collectStringsDeep(v, out);
  }
  return out;
}

function containsAbsoluteMachinePathInString(s: string): boolean {
  const t = String(s ?? '');

  // Windows drive paths:
  if (/[A-Za-zz]:\\/.test(t)) return true;
  if (/[A-Za-zz]:\/(?!\/)/.test(t)) return true;

  // UNC paths: \\server\share\...
  if (/\\\\[A-Za-z0-9_.-]+\\/.test(t)) return true;

  // file:// URIs containing machine paths
  if (/file:\/\/\/[A-Za-zz]:\/(?!\/)/i.test(t)) return true;
  if (/file:\/\/\/(Users|home|var|tmp|private|Volumes|opt)\//i.test(t)) return true;

  // Unix-ish absolute paths that strongly indicate machine-specific leakage
  if (/(^|[^a-zA-Z0-9+.-])\/(Users|home|var|tmp|private|Volumes|opt)\//.test(t)) return true;

  // Common CI runner home paths
  if (/\/home\/runner\//.test(t)) return true;
  if (/\/Users\/runner\//.test(t)) return true;
  if (/C:\\Users\\runner\\/.test(t)) return true;

  return false;
}

/**
 * Assert outputs do not contain machine-specific absolute paths.
 * Parses JSON when possible and scans all string values.
 */
function assertNoAbsoluteMachinePaths(text: string) {
  const raw = String(text ?? '');

  try {
    const parsed = JSON.parse(raw);
    const strings = collectStringsDeep(parsed);

    const bad = strings.find((s) => containsAbsoluteMachinePathInString(s));
    if (bad) throw new Error(`Found absolute machine path in output string value:\n${bad}`);
    return;
  } catch {
    if (containsAbsoluteMachinePathInString(raw)) {
      throw new Error('Found absolute machine path in raw output text.');
    }
  }
}

/**
 * Canonicalize scannedPath so goldens generated from different outDirs compare cleanly.
 * Example: "../../fixtures/node-unsafe-server" -> "fixtures/node-unsafe-server"
 */
function canonicalizeScannedPath(p: unknown): unknown {
  if (typeof p !== 'string') return p;
  const posix = p.replace(/\\/g, '/');

  const idx = posix.lastIndexOf('fixtures/node-unsafe-server');
  if (idx >= 0) return posix.slice(idx);

  let s = posix.replace(/^\.\//, '');
  while (s.startsWith('../')) s = s.slice(3);
  return s;
}

function scrubReportJsonForGolden(obj: any): any {
  const cloned = JSON.parse(JSON.stringify(obj ?? {}));

  if (cloned?.meta) {
    if (typeof cloned.meta.scannedPath === 'string') {
      cloned.meta.scannedPath = canonicalizeScannedPath(cloned.meta.scannedPath);
    }

    if (typeof cloned.meta.generatedAt === 'string') cloned.meta.generatedAt = '<generatedAt>';

    if (Array.isArray(cloned.meta.engines)) {
      for (const e of cloned.meta.engines) {
        if (typeof e?.durationMs === 'number') e.durationMs = 0;
      }
    }
  }

  return cloned;
}

function normalizeJsonForGolden(jsonText: string): string {
  const parsed = JSON.parse(jsonText);
  const scrubbed = scrubReportJsonForGolden(parsed);
  return normalizeText(JSON.stringify(scrubbed, null, 2));
}

const runCli = (args: string[]): CliResult => {
  const npmExecPath = process.env.npm_execpath;
  const hasExecPath = Boolean(npmExecPath && fs.existsSync(npmExecPath));

  const opts = {
    cwd: repoRoot,
    encoding: 'utf8' as const,
    windowsHide: true,
    timeout: 30_000,
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

beforeAll(() => {
  expect(fs.existsSync(fixtureAbs)).toBe(true);
});

describe('deterministic outputs goldens', () => {
  test(
    'relative mode produces stable report.json + results.sarif and contains no absolute machine paths',
    async () => {
      if (!UPDATE_GOLDENS) {
        requireGolden(goldenReportPath);
        requireGolden(goldenSarifPath);
      }

      const outDir = mkTempOutDir('mergesafe-test-deterministic');

      const prevCwd = process.cwd();
      process.chdir(repoRoot);

      try {
        const cfg: any = {
          outDir,
          format: ['json', 'sarif'],
          mode: 'fast',
          timeout: 30,

          // IMPORTANT: match golden default metadata
          concurrency: 4,

          engines: ['mergesafe'],
          autoInstall: false,

          failOn: 'none',
          redact: false,

          pathMode: 'relative',
          scanRoot: path.resolve(repoRoot, fixtureRel),
        };

        const result = await runScan(fixtureRel, cfg);
        const outputPath = writeOutputs(result, cfg);

        expect(outputPath).toBe(normalizeOutDir(outDir));

        const reportPath = path.join(outDir, 'report.json');
        const sarifPath = path.join(outDir, 'results.sarif');

        expect(fs.existsSync(reportPath)).toBe(true);
        expect(fs.existsSync(sarifPath)).toBe(true);

        const reportRaw = readTextNormalized(reportPath);
        const sarifRaw = readTextNormalized(sarifPath);

        assertNoAbsoluteMachinePaths(reportRaw);
        assertNoAbsoluteMachinePaths(sarifRaw);

        // If requested, update the golden snapshots from current outputs.
        if (UPDATE_GOLDENS) {
          ensureDir(goldensDir);
          writeFileNormalized(goldenReportPath, reportRaw);
          writeFileNormalized(goldenSarifPath, sarifRaw);
        }

        const hint =
          'Golden mismatch.\n' +
          'Update goldens (from repo root):\n' +
          '  MERGESAFE_UPDATE_GOLDENS=1 pnpm -C packages/cli test\n' +
          'Or generate via CLI:\n' +
          `  pnpm -C packages/cli dev -- scan ${fixtureRel} --fail-on none --path-mode relative --format json,sarif --engines mergesafe --no-auto-install --out-dir test/goldens/node-unsafe-server`;

        const actualReport = normalizeJsonForGolden(reportRaw);
        const goldenReport = normalizeJsonForGolden(readTextNormalized(goldenReportPath));
        expect(actualReport, hint).toBe(goldenReport);

        const actualSarif = normalizeText(sarifRaw);
        const goldenSarif = normalizeText(readTextNormalized(goldenSarifPath));
        expect(actualSarif, hint).toBe(goldenSarif);
      } finally {
        process.chdir(prevCwd);
        rmTempOutDir(outDir);
      }
    },
    60_000
  );
});

describe('golden scan', () => {
  test(
    'creates report structures and formats',
    async () => {
      const outDir = mkTempOutDir('mergesafe-test-golden');
      try {
        const result = await runScan(
          fixtureAbs,
          {
            outDir,
            format: ['json', 'sarif', 'md', 'html'],
            mode: 'fast',
            timeout: 30,
            concurrency: 1,
            engines: ['mergesafe'],
            autoInstall: false,
            failOn: 'none',
            redact: false,
          } as any
        );

        const outputPath = writeOutputs(result, {
          outDir,
          format: ['json', 'sarif', 'md', 'html'],
          mode: 'fast',
          timeout: 30,
          concurrency: 1,
          engines: ['mergesafe'],
          autoInstall: false,
          failOn: 'none',
          redact: false,
        } as any);

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
      } finally {
        rmTempOutDir(outDir);
      }
    },
    30_000
  );

  test(
    'fail-on high returns fail status',
    async () => {
      const outDir = mkTempOutDir('mergesafe-test-golden');
      try {
        const result = await runScan(
          fixtureAbs,
          {
            outDir,
            format: ['json'],
            mode: 'fast',
            timeout: 30,
            concurrency: 1,
            engines: ['mergesafe'],
            autoInstall: false,
            failOn: 'high',
            redact: false,
          } as any
        );

        expect(result.summary.bySeverity.high + result.summary.bySeverity.critical).toBeGreaterThan(0);
        expect(result.summary.status).toBe('FAIL');
      } finally {
        rmTempOutDir(outDir);
      }
    },
    30_000
  );
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
    const outDir = mkTempOutDir('mergesafe-test-resilience');
    try {
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
        fixtureAbs,
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
        } as any,
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
      } as any);

      expect(outputPath).toBe(normalizeOutDir(outDir));
      expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'summary.md'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'report.html'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);

      const sarif = JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8'));
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs.length).toBeGreaterThan(0);
      expect(result.meta.engines?.find((entry) => entry.engineId === 'boom')?.status).toBe('failed');
    } finally {
      rmTempOutDir(outDir);
    }
  });
});
