#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { summarize, type CliConfig, type ScanResult } from '@mergesafe/core';
import { runEngines, defaultAdapters, listEngines } from '@mergesafe/engines';
import { generateHtmlReport, generateSummaryMarkdown } from '@mergesafe/report';
import { toSarif } from '@mergesafe/sarif';

type ParsedArgs = { scanPath?: string; opts: Record<string, string | boolean>; command: 'scan' | 'list-engines' };

function parseArgs(argv: string[]): ParsedArgs {
  const normalized = argv[0] === '--' ? argv.slice(1) : argv;
  if (normalized.includes('--list-engines')) {
    const opts: Record<string, string | boolean> = {};
    for (let i = 0; i < normalized.length; i++) {
      const token = normalized[i];
      if (!token.startsWith('--')) continue;
      const key = token.slice(2);
      if (key === 'list-engines' || key === 'redact') {
        opts[key] = true;
        continue;
      }
      opts[key] = normalized[i + 1];
      i += 1;
    }
    return { command: 'list-engines', opts };
  }

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
  return { command: 'scan', scanPath, opts };
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
    engines: ((opts.engines as string) ?? (cfg.engines as unknown as string) ?? 'mergesafe').split(',').map((entry) => entry.trim()).filter(Boolean),
  };
}

export async function runScan(scanPath: string, config: CliConfig): Promise<ScanResult> {
  const selected = config.engines ?? ['mergesafe'];
  const { findings, meta } = await runEngines({ scanPath, config }, selected, defaultAdapters);
  const summary = summarize(findings, config.failOn);
  return {
    meta: {
      scannedPath: scanPath,
      generatedAt: new Date().toISOString(),
      mode: config.mode,
      timeout: config.timeout,
      concurrency: config.concurrency,
      redacted: config.redact,
      engines: meta,
    },
    summary,
    findings,
    byEngine: Object.fromEntries(meta.map((entry) => [entry.engineId, findings.filter((finding) => finding.engineSources.some((source) => source.engineId === entry.engineId)).length])),
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

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  const config = resolveConfig(parsed.opts);
  if (parsed.command === 'list-engines') {
    const entries = await listEngines({ scanPath: process.cwd(), config }, defaultAdapters);
    for (const entry of entries) {
      console.log(`${entry.engineId}\tavailable=${entry.available}\tversion=${entry.version}\thint=${entry.installHint}`);
    }
    return;
  }

  const result = await runScan(resolveScanPath(parsed.scanPath!), config);
  writeOutputs(result, config);
  console.log(`MergeSafe ${result.summary.status} grade ${result.summary.grade} findings=${result.summary.totalFindings}`);
  process.exitCode = result.summary.status === 'FAIL' ? 2 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error((err as Error).message);
    process.exit(1);
  });
}
