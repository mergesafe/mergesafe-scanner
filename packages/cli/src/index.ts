#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import YAML from 'yaml';
import { DEFAULT_ENGINES, sortFindingsDeterministic, summarize, type CliConfig, type ScanResult } from '@mergesafe/core';
import { runEngines, defaultAdapters, listEngines } from '@mergesafe/engines';
import { generateHtmlReport, generateSummaryMarkdown } from '@mergesafe/report';
import { mergeSarifRuns } from '@mergesafe/sarif';

const DEFAULT_FORMATS = ['json', 'html', 'sarif', 'md'] as const;
const ALLOWED_FORMATS = new Set(DEFAULT_FORMATS);

type CiscoMode = 'auto' | 'static' | 'known-configs' | 'config' | 'remote' | 'stdio';

type CiscoCliConfig = {
  enabled: boolean;
  mode: CiscoMode;

  // static
  toolsPath?: string;

  // config/remote/stdio
  configPath?: string;
  serverUrl?: string;
  stdioCommand?: string;
  stdioArgs?: string[];

  // auth
  bearerToken?: string;
  headers?: string[];

  // analyzers (default yara for offline)
  analyzers?: string;
};

export type CliConfigExt = CliConfig & {
  cisco?: CiscoCliConfig;
};

type OptValue = string | boolean | string[];
type ParsedArgs = {
  scanPath?: string;
  opts: Record<string, OptValue>;
  command: 'scan' | 'list-engines';
  showHelp?: boolean;
  helpTarget?: 'general' | 'scan' | 'list-engines';
};

const BOOLEAN_FLAGS = new Set([
  'list-engines',
  'redact',
  'no-auto-install',
  'help',
  'no-cisco',
]);

const REPEATABLE_FLAGS = new Set([
  'cisco-header',
  'cisco-stdio-arg',
]);

function pushOpt(opts: Record<string, OptValue>, key: string, value: string) {
  const cur = opts[key];
  if (cur === undefined) {
    opts[key] = value;
    return;
  }
  if (Array.isArray(cur)) {
    cur.push(value);
    opts[key] = cur;
    return;
  }
  // convert existing single value to array
  opts[key] = [String(cur), value];
}

function hasHelpFlag(argv: string[]): boolean {
  return argv.includes('--help') || argv.includes('-h');
}

export function getHelpText(target: ParsedArgs['helpTarget'] = 'general'): string {
  const general = [
    'MergeSafe CLI',
    '',
    'Usage:',
    '  mergesafe scan <path> [options]',
    '  mergesafe --list-engines',
    '  mergesafe --help',
    '',
    'Commands:',
    '  scan             Scan a project path and write outputs',
    '  --list-engines   List available engines and versions',
    '',
    'Run `mergesafe scan --help` for scan options.',
  ].join('\n');

  const scan = [
    'MergeSafe scan',
    '',
    'Usage:',
    '  mergesafe scan <path> [options]',
    '',
    'Options:',
    '  --out-dir <dir>                Output directory (default: mergesafe)',
    '  --format <csv>                 Output formats (default: json,html,sarif,md)',
    '  --mode <fast|deep>             Scan mode (default: fast)',
    '  --timeout <seconds>            Per-engine timeout seconds (default: 30)',
    '  --concurrency <n>              Engine concurrency (default: 4)',
    '  --fail-on <critical|high|none> Fail threshold (default: high)',
    '  --config <path>                Optional YAML config path',
    '  --engines <list>               Comma/space-separated engines list',
    '  --auto-install <true|false>    Auto-install missing tools (default: true)',
    '  --no-auto-install              Disable tool auto-install',
    '  --redact                       Redact sensitive fields in output',
    '  --no-cisco                     Remove Cisco engine from selected engines',
    '  --path-mode <relative|absolute> Output path mode (default: relative)',
  ].join('\n');

  const listEngines = [
    'MergeSafe list engines',
    '',
    'Usage:',
    '  mergesafe --list-engines',
    '',
    'Prints one line per engine as:',
    '  <engineId>\tavailable=<true|false>\tversion=<version>\thint=<installHint>',
  ].join('\n');

  if (target === 'scan') return scan;
  if (target === 'list-engines') return listEngines;
  return general;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const normalized = argv[0] === '--' ? argv.slice(1) : argv;

  // Support legacy: mergesafe --list-engines
  if (normalized.includes('--list-engines')) {
    const showHelp = hasHelpFlag(normalized);
    const opts: Record<string, OptValue> = {};
    for (let i = 0; i < normalized.length; i++) {
      const token = normalized[i];
      if (!token.startsWith('--')) continue;

      // support --key=value
      const eqIdx = token.indexOf('=');
      const key = (eqIdx >= 0 ? token.slice(2, eqIdx) : token.slice(2)).trim();
      const valueInline = eqIdx >= 0 ? token.slice(eqIdx + 1) : undefined;

      if (BOOLEAN_FLAGS.has(key)) {
        // if user wrote --flag=false, treat it as a value
        if (valueInline !== undefined) {
          opts[key] = valueInline;
        } else {
          opts[key] = true;
        }
        continue;
      }

      if (REPEATABLE_FLAGS.has(key)) {
        const val = valueInline ?? normalized[i + 1];
        if (typeof val === 'string' && val.length) pushOpt(opts, key, val);
        if (valueInline === undefined) i += 1;
        continue;
      }

      const val = valueInline ?? normalized[i + 1];
      opts[key] = val;
      if (valueInline === undefined) i += 1;
    }
    return {
      command: 'list-engines',
      opts,
      showHelp,
      helpTarget: showHelp ? 'list-engines' : undefined,
    };
  }

  const showHelp = hasHelpFlag(normalized);
  const [command, scanPath, ...rest] = normalized;

  if (showHelp) {
    if (command === 'scan') {
      return {
        command: 'scan',
        scanPath,
        opts: {},
        showHelp: true,
        helpTarget: 'scan',
      };
    }
    return {
      command: 'scan',
      opts: {},
      showHelp: true,
      helpTarget: 'general',
    };
  }

  if (command !== 'scan' || !scanPath) throw new Error('Usage: mergesafe scan <path> [options]');

  const opts: Record<string, OptValue> = {};
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith('--')) continue;

    // support --key=value
    const eqIdx = token.indexOf('=');
    const key = (eqIdx >= 0 ? token.slice(2, eqIdx) : token.slice(2)).trim();
    const valueInline = eqIdx >= 0 ? token.slice(eqIdx + 1) : undefined;

    if (BOOLEAN_FLAGS.has(key)) {
      if (valueInline !== undefined) {
        opts[key] = valueInline;
      } else {
        opts[key] = true;
      }
      continue;
    }

    if (REPEATABLE_FLAGS.has(key)) {
      const val = valueInline ?? rest[i + 1];
      if (typeof val === 'string' && val.length) pushOpt(opts, key, val);
      if (valueInline === undefined) i += 1;
      continue;
    }

    const val = valueInline ?? rest[i + 1];
    opts[key] = val;
    if (valueInline === undefined) i += 1;
  }

  return { command: 'scan', scanPath, opts };
}

function loadConfig(configPath?: string): Partial<CliConfigExt> {
  const candidate = configPath ?? (fs.existsSync('mergesafe.yml') ? 'mergesafe.yml' : undefined);
  if (!candidate || !fs.existsSync(candidate)) return {};
  const data = YAML.parse(fs.readFileSync(candidate, 'utf8'));
  return (data ?? {}) as Partial<CliConfigExt>;
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

export function parseListOpt(value: string | readonly string[] | undefined, defaults: readonly string[]): string[] {
  let raw = '';
  if (typeof value === 'string') raw = value;
  else if (Array.isArray(value)) raw = value.join(',');

  const parsed = raw
    .split(/[\s,]+/)
    .map((entry: string) => entry.trim().toLowerCase())
    .filter(Boolean);
  const deduped = [...new Set(parsed)];
  return deduped.length ? deduped : [...defaults];
}

function parseBooleanOpt(value: string | boolean | undefined, defaultValue: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
  if (['false', '0', 'no', 'off'].includes(normalized)) return false;
  return defaultValue;
}

function parseCiscoMode(raw: unknown, fallback: CiscoMode): CiscoMode {
  if (typeof raw !== 'string') return fallback;
  const v = raw.trim().toLowerCase();
  const allowed: CiscoMode[] = ['auto', 'static', 'known-configs', 'config', 'remote', 'stdio'];
  return (allowed.includes(v as CiscoMode) ? (v as CiscoMode) : fallback);
}

export function resolveConfig(opts: Record<string, OptValue>): CliConfigExt {
  const cfg = loadConfig(opts.config as string | undefined);

  const parsedFormats = parseListOpt(
    (opts.format as string | undefined) ?? (cfg.format as string | readonly string[] | undefined),
    [...DEFAULT_FORMATS]
  );
  const format = parsedFormats.filter((entry) => ALLOWED_FORMATS.has(entry as (typeof DEFAULT_FORMATS)[number]));

  // Engines list (default includes cisco unless user disables)
  const enginesFromArgs = (opts.engines as string | undefined);
  const enginesFromCfg = (cfg.engines as string | string[] | undefined);

  let engines = parseListOpt(enginesFromArgs ?? enginesFromCfg, [...DEFAULT_ENGINES]);

  // --no-cisco force removal
  const noCisco = parseBooleanOpt(opts['no-cisco'] as any, false);
  if (noCisco) engines = engines.filter((e) => e !== 'cisco');

  // Cisco settings (only meaningful if engine is selected)
  const ciscoEnabled = engines.includes('cisco');

  const ciscoToolsPath =
    (opts['cisco-tools'] as string | undefined) ??
    (cfg.cisco?.toolsPath as string | undefined);

  const ciscoMode = parseCiscoMode(
    (opts['cisco-mode'] as string | undefined) ?? (cfg.cisco?.mode as string | undefined),
    'auto'
  );

  const ciscoHeadersRaw =
    (opts['cisco-header'] as string | string[] | undefined) ??
    (cfg.cisco?.headers as unknown as string | string[] | undefined);

  const ciscoStdioArgsRaw =
    (opts['cisco-stdio-arg'] as string | string[] | undefined) ??
    (cfg.cisco?.stdioArgs as unknown as string | string[] | undefined);

  const pathModeRaw = String((opts['path-mode'] as string | undefined) ?? cfg.pathMode ?? 'relative').toLowerCase();
  const pathMode: 'relative' | 'absolute' = pathModeRaw === 'absolute' ? 'absolute' : 'relative';

  const ciscoConfig: CiscoCliConfig = {
    enabled: ciscoEnabled,
    mode: ciscoMode,

    toolsPath: ciscoToolsPath,

    configPath:
      (opts['cisco-config-path'] as string | undefined) ??
      (cfg.cisco?.configPath as string | undefined),

    serverUrl:
      (opts['cisco-server-url'] as string | undefined) ??
      (cfg.cisco?.serverUrl as string | undefined),

    stdioCommand:
      (opts['cisco-stdio-command'] as string | undefined) ??
      (cfg.cisco?.stdioCommand as string | undefined),

    stdioArgs: parseListOpt(ciscoStdioArgsRaw, []),

    bearerToken:
      (opts['cisco-bearer-token'] as string | undefined) ??
      (cfg.cisco?.bearerToken as string | undefined),

    headers: parseListOpt(ciscoHeadersRaw, []),

    analyzers:
      (opts['cisco-analyzers'] as string | undefined) ??
      (cfg.cisco?.analyzers as string | undefined) ??
      'yara',
  };

  return {
    outDir: normalizeOutDir((opts['out-dir'] as string) ?? cfg.outDir),
    format: format.length ? format : [...DEFAULT_FORMATS],
    pathMode,
    mode: ((opts.mode as CliConfig['mode']) ?? cfg.mode ?? 'fast'),
    timeout: Number((opts.timeout as string) ?? cfg.timeout ?? 30),
    concurrency: Number((opts.concurrency as string) ?? cfg.concurrency ?? 4),
    failOn: ((opts['fail-on'] as CliConfig['failOn']) ?? cfg.failOn ?? 'high'),
    redact: Boolean(opts.redact ?? cfg.redact ?? false),
    autoInstall: opts['no-auto-install']
      ? false
      : parseBooleanOpt(
          (opts['auto-install'] as string | boolean | undefined) ?? (cfg.autoInstall as boolean | undefined),
          true
        ),
    engines,

    // Extra config consumed by adapters (Step 3)
    cisco: ciscoConfig,
  };
}


function toPosix(p: string): string {
  return p.replaceAll('\\', '/');
}

function renderPath(filePath: string, scannedPath: string, mode: 'relative' | 'absolute'): string {
  const abs = path.resolve(filePath);
  if (mode === 'absolute') return toPosix(abs);
  const rel = path.relative(path.resolve(scannedPath), abs);
  if (!rel || rel.startsWith('..')) return toPosix(abs);
  return toPosix(rel);
}

function applyPathMode(result: ScanResult, pathMode: 'relative' | 'absolute'): ScanResult {
  const scannedPath = result.meta.scannedPath;
  const findings = result.findings.map((finding) => ({
    ...finding,
    locations: (finding.locations ?? []).map((loc) => ({
      ...loc,
      filePath: renderPath(loc.filePath, scannedPath, pathMode),
    })),
  }));

  return {
    ...result,
    meta: {
      ...result.meta,
      scannedPath: pathMode === 'relative' ? '.' : toPosix(path.resolve(scannedPath)),
    },
    findings: sortFindingsDeterministic(findings),
  };
}

export async function runScan(scanPath: string, config: CliConfigExt, adapters = defaultAdapters): Promise<ScanResult> {
  const selected = config.engines ?? [...DEFAULT_ENGINES];
  const { findings, meta } = await runEngines({ scanPath, config }, selected, adapters);
  const summary = summarize(findings, config.failOn);

  const baseResult: ScanResult = {
    meta: {
      scannedPath: path.resolve(scanPath),
      generatedAt: new Date().toISOString(),
      mode: config.mode,
      timeout: config.timeout,
      concurrency: config.concurrency,
      redacted: config.redact,
      engines: meta,
    },
    summary,
    findings: sortFindingsDeterministic(findings),
    byEngine: Object.fromEntries(
      meta.map((entry) => [
        entry.engineId,
        findings.filter((finding) => finding.engineSources.some((source) => source.engineId === entry.engineId)).length,
      ])
    ),
  };

  return applyPathMode(baseResult, config.pathMode ?? 'relative');
}

export function writeOutputs(result: ScanResult, config: CliConfigExt) {
  const outDirAbs = normalizeOutDir(config.outDir);
  fs.mkdirSync(outDirAbs, { recursive: true });

  const wants = new Set(
    parseListOpt(config.format as any, [...DEFAULT_FORMATS]).filter((entry) =>
      ALLOWED_FORMATS.has(entry as (typeof DEFAULT_FORMATS)[number])
    )
  );
  if (!wants.size) {
    for (const format of DEFAULT_FORMATS) wants.add(format);
  }

  if (wants.has('json')) fs.writeFileSync(path.join(outDirAbs, 'report.json'), JSON.stringify(result, null, 2));
  if (wants.has('md')) fs.writeFileSync(path.join(outDirAbs, 'summary.md'), generateSummaryMarkdown(result));
  if (wants.has('html')) fs.writeFileSync(path.join(outDirAbs, 'report.html'), generateHtmlReport(result));
  if (wants.has('sarif'))
    mergeSarifRuns({
      outDir: outDirAbs,
      enginesMeta: result.meta.engines ?? [],
      canonicalFindings: result.findings,
      redact: result.meta.redacted,
    });

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

  if (parsed.showHelp) {
    console.log(getHelpText(parsed.helpTarget));
    return;
  }

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
