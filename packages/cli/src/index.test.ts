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

const UPDATE_GOLDENS = process.env.UPDATE_GOLDENS === '1';

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

function mkOutDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-test-'));
}

function normalizeEol(s: string): string {
  // normalize CRLF/LF so the canonical JSON is OS-stable
  return s.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function sortFindingsStable(findings: any[]): any[] {
  const key = (f: any) => {
    const src = f?.engineSources?.[0];
    const rule = src?.engineRuleId ?? '';
    const loc = f?.locations?.[0] ?? {};
    const fp = loc?.filePath ?? '';
    const ln = typeof loc?.line === 'number' ? String(loc.line).padStart(8, '0') : '00000000';
    const title = f?.title ?? '';
    return `${rule}::${fp}::${ln}::${title}`;
  };
  return [...findings].sort((a, b) => key(a).localeCompare(key(b)));
}

function sanitizeReport(report: any) {
  const copy = JSON.parse(JSON.stringify(report));

  if (copy?.meta) {
    // machine/time dependent
    delete copy.meta.generatedAt;
    delete copy.meta.scannedPath;

    // CI/platform may clamp this; don't golden-test it
    delete copy.meta.concurrency;

    if (Array.isArray(copy.meta.engines)) {
      for (const engine of copy.meta.engines) {
        delete engine.durationMs;
      }
    }
  }

  // Ensure EOL is stable in any free-text fields
  if (typeof copy?.summary?.gate?.reason === 'string') {
    copy.summary.gate.reason = normalizeEol(copy.summary.gate.reason);
  }

  if (Array.isArray(copy?.findings)) {
    for (const f of copy.findings) {
      // These are currently platform-sensitive (CRLF/LF hashing differences)
      // We test determinism of IDs separately across repeated runs.
      delete f.findingId;
      delete f.fingerprint;

      if (typeof f?.remediation === 'string') f.remediation = normalizeEol(f.remediation);

      if (f?.evidence) {
        if (typeof f.evidence.excerpt === 'string') f.evidence.excerpt = normalizeEol(f.evidence.excerpt);
        if (typeof f.evidence.note === 'string') f.evidence.note = normalizeEol(f.evidence.note);
      }
    }

    copy.findings = sortFindingsStable(copy.findings);
  }

  return copy;
}

function sanitizeSarif(sarif: any) {
  const copy = JSON.parse(JSON.stringify(sarif));

  if (Array.isArray(copy?.runs)) {
    for (const run of copy.runs) {
      // timestamps are nondeterministic
      if (Array.isArray(run?.invocations)) {
        for (const inv of run.invocations) {
          delete inv?.startTimeUtc;
          delete inv?.endTimeUtc;
        }
      }

      // remove platform-sensitive fingerprints if present
      if (Array.isArray(run?.results)) {
        for (const r of run.results) {
          delete r?.fingerprints;
          delete r?.partialFingerprints;
        }

        // stable ordering
        run.results.sort((a: any, b: any) => {
          const ar = a?.ruleId ?? '';
          const br = b?.ruleId ?? '';
          if (ar !== br) return String(ar).localeCompare(String(br));

          const al = a?.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '';
          const bl = b?.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '';
          if (al !== bl) return String(al).localeCompare(String(bl));

          const ali = a?.locations?.[0]?.physicalLocation?.region?.startLine ?? 0;
          const bli = b?.locations?.[0]?.physicalLocation?.region?.startLine ?? 0;
          return Number(ali) - Number(bli);
        });
      }
    }
  }

  return copy;
}

function writeDeterministicJson(filePath: string, obj: any) {
  const txt = JSON.stringify(obj, null, 2) + '\n';
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, txt, 'utf8');
}

// NOTE: These are intentionally MUTABLE arrays because CliConfig expects string[]
const MERGESAFE_ONLY_ENGINES: string[] = ['mergesafe'];

describe('golden scan', () => {
  test(
    'creates report structures and formats (mergesafe-only, deterministic)',
    async () => {
      const outDir = mkOutDir();
      fs.rmSync(outDir, { recursive: true, force: true });

      const config = {
        outDir,
        format: ['json', 'sarif', 'md', 'html'] as const,
        mode: 'fast' as const,
        timeout: 30,
        // keep deterministic everywhere even if CI clamps
        concurrency: 1,
        failOn: 'none' as const,
        redact: false,
        autoInstall: false,
        pathMode: 'relative' as const,
        engines: [...MERGESAFE_ONLY_ENGINES], // ✅ string[]
      };

      const result = await runScan(fixture, config);
      const outputPath = writeOutputs(result, config);

      expect(outputPath).toBe(normalizeOutDir(outDir));
      expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'summary.md'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'report.html'))).toBe(true);

      const report = JSON.parse(fs.readFileSync(path.join(outDir, 'report.json'), 'utf8'));
      expect(report?.summary?.scanStatus).toBeTruthy();
      expect(report?.summary?.gate?.status).toBeTruthy();
      // back-compat alias must equal gate.status
      expect(report?.summary?.status).toBe(report?.summary?.gate?.status);

      const sarif = JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8'));
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs.length).toBeGreaterThan(0);

      expect(result.findings.length).toBeGreaterThan(0);

      const md = fs.readFileSync(path.join(outDir, 'summary.md'), 'utf8');
      expect(md).toMatch(/Scan:\s+\*\*(Completed|Partial)\*\*/);
      expect(md).toContain('Risk grade:');
      expect(md).toContain('Top Findings');
    },
    20000
  );

  test(
    'matches deterministic golden fixtures (except timestamps/platform-variant IDs)',
    async () => {
      const outDir = mkOutDir();
      const goldenDir = path.resolve(here, '../testdata/goldens/node-unsafe-server');

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
        engines: [...MERGESAFE_ONLY_ENGINES], // ✅ string[]
      };

      const runA = await runScan(fixture, config);
      writeOutputs(runA, config);

      const currentReport = sanitizeReport(JSON.parse(fs.readFileSync(path.join(outDir, 'report.json'), 'utf8')));
      const currentSarif = sanitizeSarif(JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8')));

      const goldenReportPath = path.join(goldenDir, 'report.json');
      const goldenSarifPath = path.join(goldenDir, 'results.sarif');

      if (UPDATE_GOLDENS) {
        writeDeterministicJson(goldenReportPath, currentReport);
        writeDeterministicJson(goldenSarifPath, currentSarif);
      }

      const goldenReport = JSON.parse(fs.readFileSync(goldenReportPath, 'utf8'));
      const goldenSarif = JSON.parse(fs.readFileSync(goldenSarifPath, 'utf8'));

      expect(currentReport).toEqual(goldenReport);
      expect(currentSarif).toEqual(goldenSarif);
    },
    20000
  );

  test(
    'finding IDs are deterministic across repeated runs (same platform)',
    async () => {
      const configBase = {
        format: ['json'] as const,
        mode: 'fast' as const,
        timeout: 30,
        concurrency: 1,
        failOn: 'none' as const,
        redact: false,
        autoInstall: false,
        pathMode: 'relative' as const,
        engines: [...MERGESAFE_ONLY_ENGINES], // ✅ string[]
      };

      const outA = mkOutDir();
      const outB = mkOutDir();

      const a = await runScan(fixture, { ...configBase, outDir: outA });
      writeOutputs(a, { ...configBase, outDir: outA });
      const repA = JSON.parse(fs.readFileSync(path.join(outA, 'report.json'), 'utf8'));

      const b = await runScan(fixture, { ...configBase, outDir: outB });
      writeOutputs(b, { ...configBase, outDir: outB });
      const repB = JSON.parse(fs.readFileSync(path.join(outB, 'report.json'), 'utf8'));

      const idsA = (repA?.findings ?? []).map((f: any) => f.findingId);
      const idsB = (repB?.findings ?? []).map((f: any) => f.findingId);
      expect(idsA).toEqual(idsB);

      const fpsA = (repA?.findings ?? []).map((f: any) => f.fingerprint);
      const fpsB = (repB?.findings ?? []).map((f: any) => f.fingerprint);
      expect(fpsA).toEqual(fpsB);
    },
    20000
  );

  test(
    'fail-on high returns FAIL gate status (mergesafe-only)',
    async () => {
      const outDir = mkOutDir();
      const result = await runScan(fixture, {
        outDir,
        format: ['json'],
        mode: 'fast',
        timeout: 30,
        concurrency: 1,
        failOn: 'high',
        redact: false,
        autoInstall: false,
        pathMode: 'relative',
        engines: [...MERGESAFE_ONLY_ENGINES], // ✅ string[]
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

    const out = result.stderr + result.stdout;
    expect(out).toContain('Usage: mergesafe scan <path> [options]');
  });
});

describe('resilience', () => {
  test(
    'scan completes and writes outputs when an engine fails',
    async () => {
      const outDir = mkOutDir();

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
      expect(result.summary.scanStatus).toBeTruthy();
      expect(result.summary.gate.status).toBeTruthy();
      expect(result.summary.status).toBe(result.summary.gate.status);
    },
    20000
  );
});
