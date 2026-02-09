#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import YAML from 'yaml';
import { summarize, type CliConfig, type ScanResult } from '@mergesafe/core';
import { runEngines, defaultAdapters, listEngines } from '@mergesafe/engines';
import { generateHtmlReport, generateSummaryMarkdown } from '@mergesafe/report';
import { toSarif } from '@mergesafe/sarif';

const DEFAULT_FORMATS = ['json', 'html', 'sarif', 'md'] as const;
const ALLOWED_FORMATS = new Set(DEFAULT_FORMATS);

type ParsedArgs = { scanPath?: string; opts: Record<string, string | boolean>; command: 'scan' | 'list-engines' };

function parseArgs(argv: string[]): ParsedArgs {
  const normalized = argv[0] === '--' ? argv.slice(1) : argv;

  if (normalized.includes('--list-engines')) {
    const opts: Record<string, string | boolean> = {};
    for (let i = 0; i < normalized.length; i++) {
      const token = normalized[i];
      if (!token.startsWith('--')) continue;
      const key = token.slice(2);
      if (key === 'list-engines' || key === 'redact' || key === 'no-auto-install') {
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
    if (key === 'redact' || key === 'no-auto-install') {
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

export function normalizeOutDir(
  outDir: string | undefined,
  cwd = process.cwd(),
  pathLib: Pick<typeof path, 'isAbsolute' | 'normalize' | 'resolve'> = path
): string {
  const value = outDir?.trim() || 'mergesafe';
  if (pathLib.isAbsolute(value)) return pathLib.normalize(value);
  return pathLib.resolve(cwd, value);
}

export function parseListOpt(value: string | string[] | undefined, defaults: string[]): string[] {
  const raw = Array.isArray(value) ? value.join(',') : value;
  const parsed = (raw ?? '')
    .split(/[\s,]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  const deduped = [...new Set(parsed)];
  return deduped.length ? deduped : defaults;
}


function parseBooleanOpt(value: string | boolean | undefined, defaultValue: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
  if (['false', '0', 'no', 'off'].includes(normalized)) return false;
  return defaultValue;
}

export function resolveConfig(opts: Record<string, string | boolean>): CliConfig {
  const cfg = loadConfig(opts.config as string | undefined);
  const parsedFormats = parseListOpt(
    (opts.format as string | undefined) ?? (cfg.format as string | string[] | undefined),
    [...DEFAULT_FORMATS]
  );
  const format = parsedFormats.filter((entry) => ALLOWED_FORMATS.has(entry as (typeof DEFAULT_FORMATS)[number]));

  return {
    outDir: normalizeOutDir((opts['out-dir'] as string) ?? cfg.outDir),
    format: format.length ? format : [...DEFAULT_FORMATS],
    mode: ((opts.mode as CliConfig['mode']) ?? cfg.mode ?? 'fast'),
    timeout: Number((opts.timeout as string) ?? cfg.timeout ?? 30),
    concurrency: Number((opts.concurrency as string) ?? cfg.concurrency ?? 4),
    failOn: ((opts['fail-on'] as CliConfig['failOn']) ?? cfg.failOn ?? 'high'),
    redact: Boolean(opts.redact ?? cfg.redact ?? false),
    autoInstall: opts['no-auto-install']
      ? false
      : parseBooleanOpt((opts['auto-install'] as string | boolean | undefined) ?? (cfg.autoInstall as boolean | undefined), true),
    engines: parseListOpt(
      (opts.engines as string | undefined) ?? (cfg.engines as string | string[] | undefined),
      ['mergesafe', 'semgrep', 'gitleaks']
    ),
  };
}

export async function runScan(scanPath: string, config: CliConfig): Promise<ScanResult> {
  const selected = config.engines ?? ['mergesafe', 'semgrep', 'gitleaks'];
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
    byEngine: Object.fromEntries(
      meta.map((entry) => [
        entry.engineId,
        findings.filter((finding) => finding.engineSources.some((source) => source.engineId === entry.engineId)).length,
      ])
    ),
  };
}

export function writeOutputs(result: ScanResult, config: CliConfig) {
  const outDirAbs = normalizeOutDir(config.outDir);
  fs.mkdirSync(outDirAbs, { recursive: true });

  const wants = new Set(
    parseListOpt(config.format, [...DEFAULT_FORMATS]).filter((entry) =>
      ALLOWED_FORMATS.has(entry as (typeof DEFAULT_FORMATS)[number])
    )
  );
  if (!wants.size) {
    for (const format of DEFAULT_FORMATS) wants.add(format);
  }

  if (wants.has('json')) fs.writeFileSync(path.join(outDirAbs, 'report.json'), JSON.stringify(result, null, 2));
  if (wants.has('md')) fs.writeFileSync(path.join(outDirAbs, 'summary.md'), generateSummaryMarkdown(result));
  if (wants.has('html')) fs.writeFileSync(path.join(outDirAbs, 'report.html'), generateHtmlReport(result));
  if (wants.has('sarif')) fs.writeFileSync(path.join(outDirAbs, 'results.sarif'), JSON.stringify(toSarif(result), null, 2));

  return outDirAbs;
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
  const outputPath = writeOutputs(result, config);

  console.log(`MergeSafe: wrote outputs to ${outputPath}`);
  console.log(`Engines: ${result.meta.engines?.map((entry) => `${entry.engineId}=${entry.status}`).join(' ') ?? 'none'}`);
  console.log(`MergeSafe ${result.summary.status} grade ${result.summary.grade} findings=${result.summary.totalFindings}`);
  process.exitCode = result.summary.status === 'FAIL' ? 2 : 0;
}

/**
 * IMPORTANT:
 * The old check `import.meta.url === \`file://${process.argv[1]}\`` breaks on Windows.
 * This uses pathToFileURL so it works on Windows/macOS/Linux.
 */
const isDirectRun = (() => {
  const arg1 = process.argv[1];
  if (!arg1) return false;
  try {
    return import.meta.url === pathToFileURL(arg1).href;
  } catch {
    return false;
  }
})();

if (isDirectRun) {
  main().catch((err) => {
    console.error((err as Error).stack || (err as Error).message);
    process.exit(1);
  });
}
