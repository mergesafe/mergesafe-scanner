import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { runScan, writeOutputs, normalizeOutDir, parseListOpt } from './index.js';

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
    });

    const outputPath = writeOutputs(result, {
      outDir,
      format: ['json', 'sarif', 'md', 'html'],
      mode: 'fast',
      timeout: 30,
      concurrency: 4,
      failOn: 'none',
      redact: false,
    });

    expect(outputPath).toBe(normalizeOutDir(outDir));
    expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'results.sarif'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'summary.md'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'report.html'))).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);

    const md = fs.readFileSync(path.join(outDir, 'summary.md'), 'utf8');
    expect(md).toContain('PASS');
    expect(md).toContain('Grade');
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
    });
    expect(result.summary.bySeverity.high + result.summary.bySeverity.critical).toBeGreaterThan(0);
    expect(result.summary.status).toBe('FAIL');
  });
});

describe('option parsing utilities', () => {
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
