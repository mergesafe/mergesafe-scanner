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

function execFileAllowFailure(file: string, args: string[], options: Parameters<typeof execFile>[2] = {}): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      const code = (error as any)?.code ?? 0;
      resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), code: Number(code) || 0 });
    });
  });
}

export interface EngineContext {
  scanPath: string;
  config: CliConfig;
}

export interface EngineRunResult {
  findings: Finding[];
  artifacts?: { json?: string; sarif?: string };
}

export interface EngineAdapter {
  engineId: string;
  displayName: string;
  installHint: string;
  version(): Promise<string>;
  isAvailable(ctx: EngineContext): Promise<boolean>;
  ensureAvailable?(ctx: EngineContext): Promise<void>;
  run(ctx: EngineContext): Promise<Finding[] | EngineRunResult>;
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
    return stdout.split(/\r?\n/).map((x) => x.trim()).find(Boolean);
  } catch {
    return undefined;
  }
}

export function getToolsDir(): string {
  const root = process.env.MERGESAFE_TOOLS_DIR || path.join(os.homedir(), '.mergesafe', 'tools');
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function toolsManifestPath(): string {
  return path.join(getToolsDir(), 'manifest.json');
}

function updateToolsManifest(tool: string, version: string, binaryPath: string): void {
  const file = toolsManifestPath();
  let data: Record<string, { version: string; binaryPath: string; installedAt: string }> = {};
  if (fs.existsSync(file)) {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  }
  data[tool] = { version, binaryPath, installedAt: new Date().toISOString() };
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function semgrepExecutable(venvDir: string): string {
  return process.platform === 'win32' ? path.join(venvDir, 'Scripts', 'semgrep.exe') : path.join(venvDir, 'bin', 'semgrep');
}
function pipExecutable(venvDir: string): string {
  return process.platform === 'win32' ? path.join(venvDir, 'Scripts', 'pip.exe') : path.join(venvDir, 'bin', 'pip');
}
function ciscoExecutable(venvDir: string): string {
  return process.platform === 'win32' ? path.join(venvDir, 'Scripts', 'mcp-scanner.exe') : path.join(venvDir, 'bin', 'mcp-scanner');
}

function cachedBinary(tool: string, versionTag: string, exe: string): string {
  return path.join(getToolsDir(), 'bin', tool, versionTag, exe);
}

function findFileRecursive(root: string, matcher: (name: string) => boolean): string | undefined {
  if (!fs.existsSync(root)) return undefined;
  const stack = [root];
  while (stack.length) {
    const cur = stack.pop()!;
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (matcher(entry.name)) return full;
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
  await fs.promises.mkdir(path.dirname(dest), { recursive: true });
  await fs.promises.writeFile(dest, Buffer.from(await res.arrayBuffer()));
}

function makeAssetMatcher(tool: 'gitleaks' | 'osv-scanner' | 'trivy') {
  return (name: string): boolean => {
    const value = name.toLowerCase();
    if (tool === 'osv-scanner') {
      if (process.platform === 'win32') return /windows.*amd64.*\.exe$/.test(value);
      if (process.platform === 'linux') return /linux.*amd64/.test(value);
      if (process.platform === 'darwin' && process.arch === 'arm64') return /darwin.*arm64/.test(value);
      if (process.platform === 'darwin') return /darwin.*amd64/.test(value);
    }
    if (tool === 'trivy') {
      if (process.platform === 'win32') return /windows.*64bit.*\.zip$/.test(value);
      if (process.platform === 'linux') return /linux.*64bit.*\.tar\.gz$/.test(value);
      if (process.platform === 'darwin' && process.arch === 'arm64') return /macos.*arm64.*\.tar\.gz$/.test(value);
      if (process.platform === 'darwin') return /macos.*64bit.*\.tar\.gz$/.test(value);
    }
    if (process.platform === 'win32') return /windows.*x64.*\.zip$/.test(value);
    if (process.platform === 'linux') return /linux.*x64.*\.tar\.gz$/.test(value);
    if (process.platform === 'darwin' && process.arch === 'arm64') return /darwin.*arm64.*\.tar\.gz$/.test(value);
    if (process.platform === 'darwin') return /darwin.*x64.*\.tar\.gz$/.test(value);
    return false;
  };
}

async function ensureGithubReleaseBinary(args: {
  tool: 'gitleaks' | 'osv-scanner' | 'trivy';
  owner: string;
  repo: string;
  versionEnv: string;
  defaultVersion: string;
  executableName: string;
}): Promise<string> {
  const versionTag = process.env[args.versionEnv] || args.defaultVersion;
  const exe = process.platform === 'win32' ? `${args.executableName}.exe` : args.executableName;
  const target = cachedBinary(args.tool, versionTag, exe);
  if (fs.existsSync(target)) return target;

  const releaseUrl = versionTag === 'latest'
    ? `https://api.github.com/repos/${args.owner}/${args.repo}/releases/latest`
    : `https://api.github.com/repos/${args.owner}/${args.repo}/releases/tags/${versionTag}`;
  const release = await fetchJson(releaseUrl);
  const asset = (release.assets ?? []).find((entry: any) => makeAssetMatcher(args.tool)(String(entry.name ?? '')));
  if (!asset?.browser_download_url) throw new Error(`No ${args.tool} release asset found for ${process.platform}/${process.arch}`);

  const baseDir = path.join(getToolsDir(), 'downloads', args.tool, versionTag);
  const archivePath = path.join(baseDir, String(asset.name));
  const extractDir = path.join(baseDir, 'extract');
  if (!fs.existsSync(archivePath)) await downloadFile(String(asset.browser_download_url), archivePath);
  fs.mkdirSync(extractDir, { recursive: true });

  if (String(asset.name).endsWith('.zip')) {
    await execFilePromise('powershell.exe', ['-NoProfile', '-Command', `Expand-Archive -Path "${archivePath}" -DestinationPath "${extractDir}" -Force`]);
  } else if (String(asset.name).endsWith('.tar.gz') || String(asset.name).endsWith('.tgz')) {
    await execFilePromise('tar', ['-xzf', archivePath, '-C', extractDir]);
  } else {
    fs.copyFileSync(archivePath, path.join(extractDir, path.basename(target)));
  }

  const discovered = findFileRecursive(extractDir, (name) => name.toLowerCase() === exe.toLowerCase());
  if (!discovered) throw new Error(`Downloaded ${args.tool} archive did not contain expected binary ${exe}`);

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(discovered, target);
  if (process.platform !== 'win32') fs.chmodSync(target, 0o755);
  updateToolsManifest(args.tool, versionTag, target);
  return target;
}

function existingBinary(tool: string, versionEnv: string, defaultVersion: string, executableName: string): string | undefined {
  const versionTag = process.env[versionEnv] || defaultVersion;
  const exe = process.platform === 'win32' ? `${executableName}.exe` : executableName;
  const binary = cachedBinary(tool, versionTag, exe);
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
  const venvDir = path.join(getToolsDir(), 'venvs', 'semgrep');
  const existing = semgrepExecutable(venvDir);
  if (fs.existsSync(existing)) return existing;
  const python = await resolvePythonCommand();
  if (!python) throw new Error('Python is required to auto-install semgrep.');
  await execFilePromise(python, ['-m', 'venv', venvDir]);
  const pip = pipExecutable(venvDir);
  const semgrepSpec = process.env.MERGESAFE_SEMGREP_VERSION ? `semgrep==${process.env.MERGESAFE_SEMGREP_VERSION}` : 'semgrep';
  await execFilePromise(pip, ['install', '--upgrade', 'pip'], { maxBuffer: 20 * 1024 * 1024 });
  await execFilePromise(pip, ['install', semgrepSpec], { maxBuffer: 40 * 1024 * 1024 });
  const binary = semgrepExecutable(venvDir);
  if (!fs.existsSync(binary)) throw new Error('Semgrep install completed but executable was not found in venv.');
  if (process.platform !== 'win32') fs.chmodSync(binary, 0o755);
  updateToolsManifest('semgrep', process.env.MERGESAFE_SEMGREP_VERSION || 'latest', binary);
  return binary;
}

async function ensureCiscoBinary(): Promise<string> {
  const venvDir = path.join(getToolsDir(), 'venvs', 'cisco-mcp-scanner');
  const existing = ciscoExecutable(venvDir);
  if (fs.existsSync(existing)) return existing;
  const python = await resolvePythonCommand();
  if (!python) throw new Error('Python is required to auto-install cisco mcp-scanner.');
  await execFilePromise(python, ['-m', 'venv', venvDir]);
  const pip = pipExecutable(venvDir);
  const pkgSpec = process.env.MERGESAFE_CISCO_VERSION ? `mcp-scanner==${process.env.MERGESAFE_CISCO_VERSION}` : 'mcp-scanner';
  await execFilePromise(pip, ['install', '--upgrade', 'pip'], { maxBuffer: 20 * 1024 * 1024 });
  await execFilePromise(pip, ['install', pkgSpec], { maxBuffer: 40 * 1024 * 1024 });
  if (!fs.existsSync(existing)) throw new Error('Cisco mcp-scanner install completed but executable was not found in venv.');
  if (process.platform !== 'win32') fs.chmodSync(existing, 0o755);
  updateToolsManifest('cisco', process.env.MERGESAFE_CISCO_VERSION || 'latest', existing);
  return existing;
}

function withTimeout<T>(promise: Promise<T>, timeoutSec: number, timeoutError: Error): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(timeoutError), Math.max(timeoutSec, 1) * 1000);
    promise.then((r) => { clearTimeout(timer); resolve(r); }).catch((e) => { clearTimeout(timer); reject(e); });
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
  const excerptHash = stableHash(evidenceMaterial);
  return {
    findingId: `${args.engineId}-${args.engineRuleId ?? 'rule'}-${fingerprint}`,
    title: args.title,
    severity: normalizeSeverity(args.engineSeverity ?? 'medium'),
    confidence: args.confidence ?? 'medium',
    category: args.category ?? 'mcp-security',
    owaspMcpTop10: 'MCP-A10',
    engineSources: [{ engineId: args.engineId, engineRuleId: args.engineRuleId, engineSeverity: args.engineSeverity, message: args.message }],
    locations: [{ filePath: args.filePath, line: args.line }],
    evidence: args.evidence?.trim() ? { excerpt: args.evidence, note: 'Engine finding evidence' } : { excerptHash, note: 'Evidence hash only (redacted or unavailable)' },
    remediation: args.remediation ?? 'Review and remediate based on engine guidance.',
    references: [],
    tags: [args.engineId],
    fingerprint,
  };
}

function engineArtifactBase(ctx: EngineContext, engineId: string): string {
  const outDir = path.resolve(ctx.config.outDir || 'mergesafe');
  const dir = path.join(outDir, 'artifacts', engineId);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export class MergeSafeAdapter implements EngineAdapter {
  engineId = 'mergesafe';
  displayName = 'MergeSafe deterministic rules';
  installHint = 'Built in - no install required.';
  async version() { return 'builtin'; }
  async isAvailable() { return true; }
  async run(ctx: EngineContext): Promise<Finding[]> {
    const { findings: raw } = runDeterministicRules(ctx.scanPath, ctx.config.mode);
    return raw.map((entry) => canonicalFinding({
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
    }));
  }
}

export class SemgrepAdapter implements EngineAdapter {
  engineId = 'semgrep';
  displayName = 'Semgrep (local rules only)';
  installHint = 'Auto-install semgrep into MergeSafe tools cache or install semgrep manually.';
  private resolvedBinary?: string;
  private async resolveBinary() {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = existingBinary('semgrep', 'MERGESAFE_SEMGREP_VERSION', 'latest', 'semgrep') || await resolvePathBinary('semgrep') || semgrepExecutable(path.join(getToolsDir(), 'venvs', 'semgrep'));
    return fs.existsSync(this.resolvedBinary) ? this.resolvedBinary : undefined;
  }
  async ensureAvailable() { this.resolvedBinary = await ensureSemgrepBinary(); }
  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['--version']);
    return stdout.trim() || 'unknown';
  }
  async isAvailable() { return Boolean(await this.resolveBinary()); }
  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary();
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);
    const here = path.dirname(fileURLToPath(import.meta.url));
    const configPath = path.resolve(here, '../semgrep-rules/bundle.yml');
    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');

    await execFilePromise(bin, ['--config', configPath, '--json', '--output', jsonPath, ctx.scanPath], {
      maxBuffer: 30 * 1024 * 1024,
      env: { ...process.env, SEMGREP_SEND_METRICS: 'off' },
    });
    await execFileAllowFailure(bin, ['--config', configPath, '--sarif', '--output', sarifPath, ctx.scanPath], {
      maxBuffer: 30 * 1024 * 1024,
      env: { ...process.env, SEMGREP_SEND_METRICS: 'off' },
    });

    const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as { results?: Array<Record<string, any>> };
    const findings = (parsed.results ?? []).map((item) => {
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
        evidence: ctx.config.redact ? '' : String(extra.lines ?? '').trim(),
      });
    });
    return { findings, artifacts: { json: jsonPath, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
  }
}

export class GitleaksAdapter implements EngineAdapter {
  engineId = 'gitleaks';
  displayName = 'Gitleaks';
  installHint = 'Auto-install gitleaks into MergeSafe tools cache or install gitleaks manually.';
  private resolvedBinary?: string;
  private async resolveBinary() {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = existingBinary('gitleaks', 'MERGESAFE_GITLEAKS_VERSION', 'latest', 'gitleaks') || await resolvePathBinary('gitleaks');
    return this.resolvedBinary;
  }
  async ensureAvailable() {
    this.resolvedBinary = await ensureGithubReleaseBinary({ tool: 'gitleaks', owner: 'gitleaks', repo: 'gitleaks', versionEnv: 'MERGESAFE_GITLEAKS_VERSION', defaultVersion: 'latest', executableName: 'gitleaks' });
  }
  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['version']);
    return stdout.trim() || 'unknown';
  }
  async isAvailable() { return Boolean(await this.resolveBinary()); }
  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary();
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);
    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');
    await execFileAllowFailure(bin, ['detect', '--source', ctx.scanPath, '--redact', '--report-format', 'json', '--report-path', jsonPath]);
    await execFileAllowFailure(bin, ['detect', '--source', ctx.scanPath, '--redact', '--report-format', 'sarif', '--report-path', sarifPath]);
    if (!fs.existsSync(jsonPath)) return { findings: [], artifacts: { sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
    const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as Array<Record<string, any>>;
    const findings = parsed.map((item) => canonicalFinding({
      engineId: this.engineId,
      engineRuleId: String(item.RuleID ?? item.rule ?? 'gitleaks.secret'),
      engineSeverity: 'high',
      message: String(item.Description ?? item.description ?? 'Potential secret detected'),
      title: String(item.Description ?? item.description ?? 'Potential secret detected'),
      filePath: path.resolve(ctx.scanPath, String(item.File ?? item.file ?? 'unknown')),
      line: Number(item.StartLine ?? item.startLine ?? 1),
      evidence: '',
      confidence: 'high',
      category: 'secrets',
      remediation: 'Rotate exposed credentials and remove secrets from source history.',
    }));
    return { findings, artifacts: { json: jsonPath, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
  }
}

export class CiscoMcpAdapter implements EngineAdapter {
  engineId = 'cisco';
  displayName = 'Cisco mcp-scanner (offline mode)';
  installHint = 'Auto-install mcp-scanner into MergeSafe tools cache or install mcp-scanner manually.';
  private resolvedBinary?: string;
  private async resolveBinary() {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = ciscoExecutable(path.join(getToolsDir(), 'venvs', 'cisco-mcp-scanner'));
    if (!fs.existsSync(this.resolvedBinary)) this.resolvedBinary = await resolvePathBinary('mcp-scanner');
    return this.resolvedBinary;
  }
  async ensureAvailable() { this.resolvedBinary = await ensureCiscoBinary(); }
  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout, stderr } = await execFileAllowFailure(bin, ['--version']);
    return (stdout || stderr).trim() || 'unknown';
  }
  async isAvailable() { return Boolean(await this.resolveBinary()); }
  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary();
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);
    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const cmd = ['scan', '--path', ctx.scanPath, '--output', jsonPath, '--format', 'json', '--offline'];
    const alt = ['scan', ctx.scanPath, '--output', jsonPath, '--offline'];
    let res = await execFileAllowFailure(bin, cmd, { maxBuffer: 30 * 1024 * 1024, env: { ...process.env, MCP_SCANNER_OFFLINE: '1' } });
    if (res.code !== 0 && !fs.existsSync(jsonPath)) {
      res = await execFileAllowFailure(bin, alt, { maxBuffer: 30 * 1024 * 1024, env: { ...process.env, MCP_SCANNER_OFFLINE: '1' } });
    }
    if (!fs.existsSync(jsonPath)) throw new Error(`Cisco scan failed: ${(res.stderr || res.stdout).trim() || 'unknown error'}`);
    const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as any;
    const issues = Array.isArray(raw) ? raw : (raw.findings ?? raw.issues ?? []);
    const findings: Finding[] = (issues as any[]).map((item: any) => canonicalFinding({
      engineId: this.engineId,
      engineRuleId: String(item.rule_id ?? item.ruleId ?? item.id ?? 'cisco.mcp'),
      engineSeverity: String(item.severity ?? 'medium'),
      message: String(item.message ?? item.title ?? 'Cisco MCP finding'),
      title: String(item.title ?? item.message ?? 'Cisco MCP finding'),
      filePath: path.resolve(ctx.scanPath, String(item.file ?? item.path ?? 'unknown')),
      line: Number(item.line ?? item.start_line ?? 1),
      evidence: ctx.config.redact ? '' : String(item.snippet ?? ''),
    }));
    return { findings, artifacts: { json: jsonPath } };
  }
}

export class OsvScannerAdapter implements EngineAdapter {
  engineId = 'osv';
  displayName = 'OSV-Scanner';
  installHint = 'Auto-install osv-scanner into MergeSafe tools cache or install osv-scanner manually.';
  private resolvedBinary?: string;
  private async resolveBinary() {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = existingBinary('osv-scanner', 'MERGESAFE_OSV_VERSION', 'latest', 'osv-scanner') || await resolvePathBinary('osv-scanner');
    return this.resolvedBinary;
  }
  async ensureAvailable() {
    this.resolvedBinary = await ensureGithubReleaseBinary({ tool: 'osv-scanner', owner: 'google', repo: 'osv-scanner', versionEnv: 'MERGESAFE_OSV_VERSION', defaultVersion: 'latest', executableName: 'osv-scanner' });
  }
  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['--version']);
    return stdout.trim() || 'unknown';
  }
  async isAvailable() { return Boolean(await this.resolveBinary()); }
  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary();
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);
    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');
    await execFileAllowFailure(bin, ['scan', 'source', '-r', ctx.scanPath, '--format', 'json', '--output', jsonPath]);
    await execFileAllowFailure(bin, ['scan', 'source', '-r', ctx.scanPath, '--format', 'sarif', '--output', sarifPath]);
    if (!fs.existsSync(jsonPath)) return { findings: [], artifacts: { sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
    const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as any;
    const vulns = (raw.results ?? []).flatMap((entry: any) => entry.packages?.flatMap((p: any) => p.vulnerabilities ?? []) ?? entry.vulnerabilities ?? []);
    const findings: Finding[] = (vulns as any[]).map((v: any) => canonicalFinding({
      engineId: this.engineId,
      engineRuleId: String(v.id ?? 'OSV'),
      engineSeverity: 'high',
      message: String(v.summary ?? v.details ?? 'Vulnerable dependency'),
      title: `Dependency vulnerability ${String(v.id ?? '')}`.trim(),
      filePath: path.resolve(ctx.scanPath, String(v.database_specific?.source ?? 'dependencies')),
      line: 1,
      evidence: '',
      confidence: 'high',
      category: 'dependencies',
      remediation: 'Update vulnerable dependency to a fixed version.',
    }));
    return { findings, artifacts: { json: jsonPath, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
  }
}

export class TrivyAdapter implements EngineAdapter {
  engineId = 'trivy';
  displayName = 'Trivy';
  installHint = 'Auto-install trivy into MergeSafe tools cache or install trivy manually.';
  private resolvedBinary?: string;
  private async resolveBinary() {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = existingBinary('trivy', 'MERGESAFE_TRIVY_VERSION', 'latest', 'trivy') || await resolvePathBinary('trivy');
    return this.resolvedBinary;
  }
  async ensureAvailable() {
    this.resolvedBinary = await ensureGithubReleaseBinary({ tool: 'trivy', owner: 'aquasecurity', repo: 'trivy', versionEnv: 'MERGESAFE_TRIVY_VERSION', defaultVersion: 'latest', executableName: 'trivy' });
  }
  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['--version']);
    return stdout.split('\n')[0]?.trim() || 'unknown';
  }
  async isAvailable() { return Boolean(await this.resolveBinary()); }
  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary();
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);
    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');
    await execFileAllowFailure(bin, ['fs', '--format', 'json', '--output', jsonPath, ctx.scanPath]);
    await execFileAllowFailure(bin, ['fs', '--format', 'sarif', '--output', sarifPath, ctx.scanPath]);
    return { findings: [], artifacts: { json: fs.existsSync(jsonPath) ? jsonPath : undefined, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
  }
}

export const defaultAdapters: EngineAdapter[] = [
  new MergeSafeAdapter(),
  new SemgrepAdapter(),
  new GitleaksAdapter(),
  new CiscoMcpAdapter(),
  new OsvScannerAdapter(),
  new TrivyAdapter(),
];

export async function listEngines(ctx: EngineContext, adapters: EngineAdapter[] = defaultAdapters) {
  return Promise.all(adapters.map(async (adapter) => ({
    engineId: adapter.engineId,
    displayName: adapter.displayName,
    available: await adapter.isAvailable(ctx),
    version: await adapter.version(),
    installHint: adapter.installHint,
  })));
}

export async function runEngines(
  ctx: EngineContext,
  selectedEngines: string[],
  adapters: EngineAdapter[] = defaultAdapters,
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
          meta.push({
            engineId: adapter.engineId,
            displayName: adapter.displayName,
            version,
            status: 'failed',
            durationMs: Date.now() - start,
            installHint: adapter.installHint,
            errorMessage: `Auto-install failed: ${(error as Error).message}`,
          });
          continue;
        }
      }

      if (!available) {
        meta.push({
          engineId: adapter.engineId,
          displayName: adapter.displayName,
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
        const normalized: EngineRunResult = Array.isArray(result) ? { findings: result } : result;
        findings.push(...normalized.findings);
        meta.push({
          engineId: adapter.engineId,
          displayName: adapter.displayName,
          version,
          status: 'ok',
          durationMs: Date.now() - start,
          artifacts: normalized.artifacts,
        });
      } catch (error) {
        const err = error as Error;
        const timeout = /timed out/i.test(err.message);
        meta.push({
          engineId: adapter.engineId,
          displayName: adapter.displayName,
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
