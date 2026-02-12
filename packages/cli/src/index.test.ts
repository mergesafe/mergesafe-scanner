//packages/cli/src/index.test.ts

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { runScan, writeOutputs, normalizeOutDir, parseListOpt, resolveConfig } from './index.js';
import type { EngineAdapter } from '@mergesafe/engines';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(here, '../../../fixtures/node-unsafe-server');
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mergesafe-test-golden-'));

describe('golden scan', () => {
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
});

describe('option parsing utilities', () => {

  test('resolveConfig defaults engines to multi-engine and auto-install on', () => {
    const config = resolveConfig({});
    expect(config.engines).toEqual(['mergesafe', 'semgrep', 'gitleaks', 'cisco', 'osv']);
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


describe('resilience', () => {
  test('scan completes and writes outputs when an engine fails', async () => {
    const failingAdapter: EngineAdapter = {
      engineId: 'boom',
      displayName: 'Boom engine',
      installHint: 'none',
      async version() { return '1.0'; },
      async isAvailable() { return true; },
      async run() { throw new Error('simulated failure'); },
    };

    const result = await runScan(fixture, {
      outDir,
      format: ['json', 'sarif', 'md', 'html'],
      mode: 'fast',
      timeout: 30,
      concurrency: 1,
      failOn: 'none',
      redact: false,
      autoInstall: false,
      engines: ['boom'],
    }, [failingAdapter]);

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
