#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { dedupeFindings, summarize, type CliConfig, type ScanResult } from '@mergesafe/core';
import { runDeterministicRules } from '@mergesafe/rules';
import { generateHtmlReport, generateSummaryMarkdown } from '@mergesafe/report';
import { toSarif } from '@mergesafe/sarif';

function parseArgs(argv: string[]) {
  const normalized = argv[0] === "--" ? argv.slice(1) : argv;
  const [command, scanPath, ...rest] = normalized;
  if (command !== 'scan' || !scanPath) throw new Error('Usage: mergesafe scan <path> [options]');
  const opts: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    if (key === 'redact') {
      opts[key] = true;
      continue;
    }
    opts[key] = rest[i + 1];
    i++;
  }
  return { scanPath, opts };
}

function loadConfig(configPath?: string): Partial<CliConfig> {
  const candidate = configPath ?? (fs.existsSync('mergesafe.yml') ? 'mergesafe.yml' : undefined);
  if (!candidate || !fs.existsSync(candidate)) return {};
  const data = YAML.parse(fs.readFileSync(candidate, 'utf8'));
  return data ?? {};
}


function resolveOutDir(dir: string): string {
  if (path.isAbsolute(dir)) return dir;
  const repoRoot = path.resolve(process.cwd(), '..', '..');
  if (fs.existsSync(path.join(repoRoot, 'pnpm-workspace.yaml'))) {
    return path.resolve(repoRoot, dir);
  }
  return path.resolve(process.cwd(), dir);
}

function resolveConfig(opts: Record<string, string | boolean>): CliConfig {
  const cfg = loadConfig((opts.config as string | undefined));
  return {
    outDir: resolveOutDir(((opts['out-dir'] as string) ?? cfg.outDir ?? 'mergesafe') as string),
    format: ((opts.format as string) ?? (cfg.format as unknown as string) ?? 'json,html,sarif,md').split(',').map((x) => x.trim()),
    mode: ((opts.mode as CliConfig['mode']) ?? cfg.mode ?? 'fast'),
    timeout: Number((opts.timeout as string) ?? cfg.timeout ?? 30),
    concurrency: Number((opts.concurrency as string) ?? cfg.concurrency ?? 4),
    failOn: ((opts['fail-on'] as CliConfig['failOn']) ?? cfg.failOn ?? 'high'),
    redact: Boolean(opts.redact ?? cfg.redact ?? false),
  };
}

export function runScan(scanPath: string, config: CliConfig): ScanResult {
  const { findings: rawFindings, tools } = runDeterministicRules(scanPath, config.mode);
  const findings = dedupeFindings(rawFindings, config.redact);
  const summary = summarize(findings, config.failOn);
  return {
    meta: {
      scannedPath: scanPath,
      generatedAt: new Date().toISOString(),
      mode: config.mode,
      timeout: config.timeout,
      concurrency: config.concurrency,
      redacted: config.redact,
    },
    summary,
    findings,
    byEngine: { mergesafe: findings.length, toolSurface: tools.length },
  };
}

function writeOutputs(result: ScanResult, config: CliConfig) {
  fs.mkdirSync(config.outDir, { recursive: true });
  const wants = new Set(config.format);
  if (wants.has('json')) fs.writeFileSync(path.join(config.outDir, 'report.json'), JSON.stringify(result, null, 2));
  if (wants.has('md')) fs.writeFileSync(path.join(config.outDir, 'summary.md'), generateSummaryMarkdown(result));
  if (wants.has('html')) fs.writeFileSync(path.join(config.outDir, 'report.html'), generateHtmlReport(result));
  if (wants.has('sarif')) fs.writeFileSync(path.join(config.outDir, 'results.sarif'), JSON.stringify(toSarif(result), null, 2));
}


function resolveScanPath(inputPath: string): string {
  const abs = path.resolve(process.cwd(), inputPath);
  if (fs.existsSync(abs)) return abs;
  const repoRelative = path.resolve(process.cwd(), '..', '..', inputPath);
  if (fs.existsSync(repoRelative)) return repoRelative;
  return abs;
}

function main() {
  const { scanPath, opts } = parseArgs(process.argv.slice(2));
  const config = resolveConfig(opts);
  const result = runScan(resolveScanPath(scanPath), config);
  writeOutputs(result, config);
  console.log(`MergeSafe ${result.summary.status} grade ${result.summary.grade} findings=${result.summary.totalFindings}`);
  process.exitCode = result.summary.status === 'FAIL' ? 2 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }
}
