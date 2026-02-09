import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  findingFingerprint,
  mergeCanonicalFindings,
  stableHash,
  type CliConfig,
  type Confidence,
  type EngineExecutionMeta,
  type Finding,
  type Severity,
} from '@mergesafe/core';
import { runDeterministicRules } from '@mergesafe/rules';


function execFilePromise(file: string, args: string[], options: Parameters<typeof execFile>[2] = {}): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
    });
  });
}

export interface EngineContext {
  scanPath: string;
  config: CliConfig;
}

export interface EngineAdapter {
  engineId: string;
  displayName: string;
  installHint: string;
  version(): Promise<string>;
  isAvailable(ctx: EngineContext): Promise<boolean>;
  ensureAvailable?(ctx: EngineContext): Promise<void>;
  run(ctx: EngineContext): Promise<Finding[]>;
}

function normalizeSeverity(input: string, fallback: Severity = 'medium'): Severity {
  const key = input.toLowerCase();
  if (key === 'error' || key === 'critical') return 'critical';
  if (key === 'warning' || key === 'high') return 'high';
  if (key === 'medium') return 'medium';
  if (key === 'low') return 'low';
  if (key === 'info' || key === 'note') return 'info';
  return fallback;
}

function quoteShellArg(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export async function hasBinary(name: string): Promise<boolean> {
  try {
    if (process.platform === 'win32') {
      await execFilePromise('where.exe', [name]);
    } else {
      await execFilePromise('sh', ['-lc', `command -v ${quoteShellArg(name)}`]);
    }
    return true;
  } catch {
    return false;
  }
}

async function resolvePathBinary(name: string): Promise<string | undefined> {
  try {
    const { stdout } =
      process.platform === 'win32'
        ? await execFilePromise('where.exe', [name])
        : await execFilePromise('sh', ['-lc', `command -v ${quoteShellArg(name)}`]);
    const candidate = stdout
      .split(/\r?\n/)
      .map((entry) => entry.trim())
      .find(Boolean);
    return candidate || undefined;
  } catch {
    return undefined;
  }
}

export function getToolsDir(): string {
  const root = process.env.MERGESAFE_TOOLS_DIR || path.join(os.homedir(), '.mergesafe', 'tools');
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function semgrepExecutable(venvDir: string): string {
  return process.platform === 'win32' ? path.join(venvDir, 'Scripts', 'semgrep.exe') : path.join(venvDir, 'bin', 'semgrep');
}

function semgrepPipExecutable(venvDir: string): string {
  return process.platform === 'win32' ? path.join(venvDir, 'Scripts', 'pip.exe') : path.join(venvDir, 'bin', 'pip');
}

function gitleaksCachedBinary(versionTag: string): string {
  const exe = process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks';
  return path.join(getToolsDir(), 'gitleaks', versionTag, exe);
}

function findFileRecursive(root: string, matcher: (name: string) => boolean): string | undefined {
  if (!fs.existsSync(root)) return undefined;
  const stack = [root];
  while (stack.length) {
    const cur = stack.pop()!;
    const entries = fs.readdirSync(cur, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (matcher(entry.name)) return fullPath;
    }
  }
  return undefined;
}

async function fetchJson(url: string): Promise<any> {
  const res = await fetch(url, { headers: { 'User-Agent': 'mergesafe-scanner' } });
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
  return res.json();
}

async function downloadFile(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { headers: { 'User-Agent': 'mergesafe-scanner' } });
  if (!res.ok) throw new Error(`Failed download ${url}: ${res.status}`);
  const data = Buffer.from(await res.arrayBuffer());
  await fs.promises.mkdir(path.dirname(dest), { recursive: true });
  await fs.promises.writeFile(dest, data);
}

function gitleaksAssetMatcher(name: string): boolean {
  const value = name.toLowerCase();
  if (process.platform === 'win32') return /windows.*x64.*\.zip$/.test(value);
  if (process.platform === 'linux') return /linux.*x64.*\.tar\.gz$/.test(value);
  if (process.platform === 'darwin' && process.arch === 'arm64') return /darwin.*arm64.*\.tar\.gz$/.test(value);
  if (process.platform === 'darwin') return /darwin.*x64.*\.tar\.gz$/.test(value);
  return false;
}

export async function ensureGitleaksBinary(): Promise<string> {
  const versionTag = process.env.MERGESAFE_GITLEAKS_VERSION || 'latest';
  const cached = gitleaksCachedBinary(versionTag);
  if (fs.existsSync(cached)) return cached;

  const releaseUrl = versionTag === 'latest'
    ? 'https://api.github.com/repos/gitleaks/gitleaks/releases/latest'
    : `https://api.github.com/repos/gitleaks/gitleaks/releases/tags/${versionTag}`;
  const release = await fetchJson(releaseUrl);
  const asset = (release.assets ?? []).find((entry: any) => gitleaksAssetMatcher(String(entry.name ?? '')));
  if (!asset?.browser_download_url) {
    throw new Error(`No supported gitleaks release asset found for ${process.platform}/${process.arch}`);
  }

  const downloadDir = path.join(getToolsDir(), 'gitleaks', versionTag, 'download');
  const extractDir = path.join(getToolsDir(), 'gitleaks', versionTag, 'extract');
  fs.mkdirSync(downloadDir, { recursive: true });
  fs.mkdirSync(extractDir, { recursive: true });

  const archivePath = path.join(downloadDir, String(asset.name));
  if (!fs.existsSync(archivePath)) {
    await downloadFile(String(asset.browser_download_url), archivePath);
  }

  if (String(asset.name).endsWith('.zip')) {
    await execFilePromise('powershell.exe', ['-NoProfile', '-Command', `Expand-Archive -Path "${archivePath}" -DestinationPath "${extractDir}" -Force`]);
  } else {
    await execFilePromise('tar', ['-xzf', archivePath, '-C', extractDir]);
  }

  const discovered = findFileRecursive(extractDir, (name) =>
    process.platform === 'win32' ? name.toLowerCase() === 'gitleaks.exe' : name === 'gitleaks'
  );
  if (!discovered) throw new Error('Downloaded gitleaks archive did not contain a gitleaks binary');

  const target = gitleaksCachedBinary(versionTag);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(discovered, target);
  if (process.platform !== 'win32') fs.chmodSync(target, 0o755);
  return target;
}

function existingSemgrepBinary(): string | undefined {
  const venv = path.join(getToolsDir(), 'semgrep', 'venv');
  const binary = semgrepExecutable(venv);
  return fs.existsSync(binary) ? binary : undefined;
}

function existingGitleaksBinary(): string | undefined {
  const versionTag = process.env.MERGESAFE_GITLEAKS_VERSION || 'latest';
  const binary = gitleaksCachedBinary(versionTag);
  return fs.existsSync(binary) ? binary : undefined;
}

function resolvePythonCommand(): Promise<string | undefined> {
  return (async () => {
    for (const candidate of process.platform === 'win32' ? ['py', 'python', 'python3'] : ['python3', 'python']) {
      if (await hasBinary(candidate)) return candidate;
    }
    return undefined;
  })();
}

export async function ensureSemgrepBinary(): Promise<string> {
  const found = existingSemgrepBinary();
  if (found) return found;

  const python = await resolvePythonCommand();
  if (!python) throw new Error('Python is required to auto-install semgrep. Install Python or run with --no-auto-install.');

  const semgrepRoot = path.join(getToolsDir(), 'semgrep');
  const venvDir = path.join(semgrepRoot, 'venv');
  fs.mkdirSync(semgrepRoot, { recursive: true });
  await execFilePromise(python, ['-m', 'venv', venvDir]);

  const pip = semgrepPipExecutable(venvDir);
  const semgrepSpec = process.env.MERGESAFE_SEMGREP_VERSION ? `semgrep==${process.env.MERGESAFE_SEMGREP_VERSION}` : 'semgrep';
  await execFilePromise(pip, ['install', '--upgrade', 'pip'], { maxBuffer: 20 * 1024 * 1024 });
  await execFilePromise(pip, ['install', semgrepSpec], { maxBuffer: 40 * 1024 * 1024 });

  const binary = semgrepExecutable(venvDir);
  if (!fs.existsSync(binary)) throw new Error('Semgrep install completed but executable was not found in venv.');
  if (process.platform !== 'win32') fs.chmodSync(binary, 0o755);
  return binary;
}

function withTimeout<T>(promise: Promise<T>, timeoutSec: number, timeoutError: Error): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(timeoutError), Math.max(timeoutSec, 1) * 1000);
    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

function canonicalFinding(args: {
  engineId: string;
  engineRuleId?: string;
  engineSeverity?: string;
  message: string;
  title: string;
  filePath: string;
  line: number;
  evidence: string;
  confidence?: Confidence;
  category?: string;
  remediation?: string;
}): Finding {
  const evidenceMaterial = args.evidence?.trim() ? args.evidence : `${args.engineId}:${args.engineRuleId ?? ''}:${args.message}`;
  const fingerprint = findingFingerprint(args.filePath, args.line, evidenceMaterial);
  const severity = normalizeSeverity(args.engineSeverity ?? 'medium');
  const excerptHash = stableHash(evidenceMaterial);

  return {
    findingId: `${args.engineId}-${args.engineRuleId ?? 'rule'}-${fingerprint}`,
    title: args.title,
    severity,
    confidence: args.confidence ?? 'medium',
    category: args.category ?? 'mcp-security',
    owaspMcpTop10: 'MCP-A10',
    engineSources: [
      {
        engineId: args.engineId,
        engineRuleId: args.engineRuleId,
        engineSeverity: args.engineSeverity,
        message: args.message,
      },
    ],
    locations: [{ filePath: args.filePath, line: args.line }],
    evidence: args.evidence?.trim()
      ? { excerpt: args.evidence, note: 'Engine finding evidence' }
      : { excerptHash, note: 'Evidence hash only (redacted or unavailable)' },
    remediation: args.remediation ?? 'Review and remediate based on engine guidance.',
    references: [],
    tags: [args.engineId],
    fingerprint,
  };
}

export class MergeSafeAdapter implements EngineAdapter {
  engineId = 'mergesafe';
  displayName = 'MergeSafe deterministic rules';
  installHint = 'Built in - no install required.';

  async version(): Promise<string> {
    return 'builtin';
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    const { findings: raw } = runDeterministicRules(ctx.scanPath, ctx.config.mode);
    return raw.map((entry) =>
      canonicalFinding({
        engineId: this.engineId,
        engineRuleId: entry.ruleId,
        engineSeverity: entry.severity,
        message: entry.title,
        title: entry.title,
        filePath: entry.filePath,
        line: entry.line,
        evidence: ctx.config.redact ? '' : entry.evidence,
        confidence: entry.confidence,
        category: entry.category,
        remediation: entry.remediation,
      })
    );
  }
}

export class SemgrepAdapter implements EngineAdapter {
  engineId = 'semgrep';
  displayName = 'Semgrep (local rules only)';
  installHint = 'Install semgrep locally (pip install semgrep) or use --no-auto-install to skip this engine.';
  private resolvedBinary?: string;

  private async resolveBinary(): Promise<string | undefined> {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = (await resolvePathBinary('semgrep')) || existingSemgrepBinary();
    return this.resolvedBinary;
  }

  async ensureAvailable(): Promise<void> {
    this.resolvedBinary = await ensureSemgrepBinary();
  }

  async version(): Promise<string> {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    try {
      const { stdout } = await execFilePromise(bin, ['--version']);
      return stdout.trim() || 'unknown';
    } catch {
      return 'unavailable';
    }
  }

  async isAvailable(): Promise<boolean> {
    return Boolean(await this.resolveBinary());
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    const semgrepBinary = await this.resolveBinary();
    if (!semgrepBinary) throw new Error(`Not installed. ${this.installHint}`);

    const here = path.dirname(fileURLToPath(import.meta.url));
    const rulesDir = path.resolve(here, '../semgrep-rules');

    const { stdout } = await execFilePromise(
      semgrepBinary,
      ['--config', rulesDir, '--json', '--metrics=off', ctx.scanPath],
      { maxBuffer: 20 * 1024 * 1024 }
    );

    const parsed = JSON.parse(stdout) as { results?: Array<Record<string, any>> };

    return (parsed.results ?? []).map((item) => {
      const extra = (item.extra ?? {}) as Record<string, any>;
      const start = (item.start ?? {}) as Record<string, any>;

      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: String(item.check_id ?? 'semgrep.rule'),
        engineSeverity: String(extra.severity ?? 'INFO'),
        message: String(extra.message ?? item.path ?? 'Semgrep finding'),
        title: String(extra.message ?? 'Semgrep finding'),
        filePath: path.resolve(ctx.scanPath, String(item.path ?? 'unknown')),
        line: Number(start.line ?? 1),
        evidence: ctx.config.redact ? '' : String((extra.lines ?? '').toString().trim()),
        confidence: 'medium',
      });
    });
  }
}

export class GitleaksAdapter implements EngineAdapter {
  engineId = 'gitleaks';
  displayName = 'Gitleaks';
  installHint = 'Install gitleaks locally or use --no-auto-install to skip this engine.';
  private resolvedBinary?: string;

  private async resolveBinary(): Promise<string | undefined> {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = (await resolvePathBinary('gitleaks')) || existingGitleaksBinary();
    return this.resolvedBinary;
  }

  async ensureAvailable(): Promise<void> {
    this.resolvedBinary = await ensureGitleaksBinary();
  }

  async version(): Promise<string> {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    try {
      const { stdout } = await execFilePromise(bin, ['version']);
      return stdout.trim() || 'unknown';
    } catch {
      return 'unavailable';
    }
  }

  async isAvailable(): Promise<boolean> {
    return Boolean(await this.resolveBinary());
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    const gitleaksBinary = await this.resolveBinary();
    if (!gitleaksBinary) throw new Error(`Not installed. ${this.installHint}`);

    const reportPath = path.join(os.tmpdir(), `mergesafe-gitleaks-${Date.now()}.json`);
    try {
      await execFilePromise(
        gitleaksBinary,
        ['detect', '--source', ctx.scanPath, '--report-format', 'json', '--report-path', reportPath, '--redact'],
        { maxBuffer: 10 * 1024 * 1024 }
      );
    } catch {
      // gitleaks returns non-zero when findings exist; continue parsing report.
    }

    if (!fs.existsSync(reportPath)) return [];
    const parsed = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as Array<Record<string, any>>;

    return parsed.map((item) => {
      const file = String(item.File ?? item.file ?? 'unknown');
      const line = Number(item.StartLine ?? item.startLine ?? 1);
      const rule = String(item.RuleID ?? item.rule ?? 'gitleaks.secret');
      const description = String(item.Description ?? item.description ?? 'Potential secret detected');
      const fingerprintMaterial = [item.Fingerprint, item.Commit, item.Author].filter(Boolean).join(':') || description;

      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: rule,
        engineSeverity: 'high',
        message: description,
        title: description,
        filePath: path.resolve(ctx.scanPath, file),
        line,
        evidence: ctx.config.redact ? '' : stableHash(String(fingerprintMaterial)),
        confidence: 'high',
        category: 'secrets',
        remediation: 'Rotate exposed credentials and remove secrets from source history.',
      });
    });
  }
}

export const defaultAdapters: EngineAdapter[] = [new MergeSafeAdapter(), new SemgrepAdapter(), new GitleaksAdapter()];

export async function listEngines(ctx: EngineContext, adapters: EngineAdapter[] = defaultAdapters) {
  return Promise.all(
    adapters.map(async (adapter) => ({
      engineId: adapter.engineId,
      displayName: adapter.displayName,
      available: await adapter.isAvailable(ctx),
      version: await adapter.version(),
      installHint: adapter.installHint,
    }))
  );
}

export async function runEngines(
  ctx: EngineContext,
  selectedEngines: string[],
  adapters: EngineAdapter[] = defaultAdapters
): Promise<{ findings: Finding[]; meta: EngineExecutionMeta[] }> {
  const selected = adapters.filter((adapter) => selectedEngines.includes(adapter.engineId));
  const findings: Finding[] = [];
  const meta: EngineExecutionMeta[] = [];
  const queue = [...selected];
  const limit = Math.max(1, ctx.config.concurrency);

  const workers = new Array(Math.min(limit, queue.length)).fill(0).map(async () => {
    while (queue.length > 0) {
      const adapter = queue.shift();
      if (!adapter) break;

      const start = Date.now();
      let version = await adapter.version();
      let available = await adapter.isAvailable(ctx);

      if (!available && ctx.config.autoInstall && adapter.ensureAvailable) {
        try {
          await adapter.ensureAvailable(ctx);
          available = await adapter.isAvailable(ctx);
          version = await adapter.version();
        } catch (error) {
          const err = error as Error;
          meta.push({
            engineId: adapter.engineId,
            version,
            status: 'failed',
            durationMs: Date.now() - start,
            installHint: adapter.installHint,
            errorMessage: `Auto-install failed: ${err.message}`,
          });
          continue;
        }

        if (!available) {
          meta.push({
            engineId: adapter.engineId,
            version,
            status: 'failed',
            durationMs: Date.now() - start,
            installHint: adapter.installHint,
            errorMessage: `Auto-install failed. ${adapter.installHint}`,
          });
          continue;
        }
      }

      if (!available) {
        meta.push({
          engineId: adapter.engineId,
          version,
          status: 'skipped',
          durationMs: Date.now() - start,
          installHint: adapter.installHint,
          errorMessage: `Not installed. ${adapter.installHint}`,
        });
        continue;
      }

      try {
        const result = await withTimeout(adapter.run(ctx), ctx.config.timeout, new Error(`Timed out after ${ctx.config.timeout}s`));
        findings.push(...result);
        meta.push({ engineId: adapter.engineId, version, status: 'ok', durationMs: Date.now() - start });
      } catch (error) {
        const err = error as Error;
        const timeout = /timed out/i.test(err.message);
        meta.push({
          engineId: adapter.engineId,
          version,
          status: timeout ? 'timeout' : 'failed',
          durationMs: Date.now() - start,
          errorMessage: err.message,
        });
      }
    }
  });

  await Promise.all(workers);

  return {
    findings: mergeCanonicalFindings(findings),
    meta: meta.sort((a, b) => selectedEngines.indexOf(a.engineId) - selectedEngines.indexOf(b.engineId)),
  };
}
