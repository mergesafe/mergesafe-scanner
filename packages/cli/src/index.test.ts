import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { runScan } from './index.js';
import { toSarif } from '@mergesafe/sarif';
import { generateSummaryMarkdown, generateHtmlReport } from '@mergesafe/report';

const here = path.dirname(new URL(import.meta.url).pathname);
const fixture = path.resolve(here, '../../../fixtures/node-unsafe-server');
const outDir = path.resolve(here, '../../../mergesafe-test-golden');

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

    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify(result, null, 2));
    fs.writeFileSync(path.join(outDir, 'results.sarif'), JSON.stringify(toSarif(result), null, 2));
    fs.writeFileSync(path.join(outDir, 'summary.md'), generateSummaryMarkdown(result));
    fs.writeFileSync(path.join(outDir, 'report.html'), generateHtmlReport(result));

    expect(fs.existsSync(path.join(outDir, 'report.json'))).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);

    const sarif = JSON.parse(fs.readFileSync(path.join(outDir, 'results.sarif'), 'utf8'));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs?.[0]?.tool?.driver?.name).toBe('MergeSafe');

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
    expect(result.summary.status).toBe('FAIL');
  });
});
