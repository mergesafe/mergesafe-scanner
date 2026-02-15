// engines/src/index.ts
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
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
  type CiscoConfig,
  type CiscoMode,
  type VerifyDownloadsMode,
} from '@mergesafe/core';
import { runDeterministicRules } from '@mergesafe/rules';
import { TOOL_MANIFEST, resolveToolArtifact, type ToolName } from './toolManifest.js';

function execFilePromise(
  file: string,
  args: string[],
  options: Parameters<typeof execFile>[2] = {}
): Promise<{ stdout: string; stderr: string }> {
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

function execFileAllowFailure(
  file: string,
  args: string[],
  options: Parameters<typeof execFile>[2] = {}
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      // if error.code is a string (e.g., ENOENT), do NOT coerce to 0
      const rawCode = (error as any)?.code;
      const code = typeof rawCode === 'number' ? rawCode : error ? 1 : 0;

      resolve({
        stdout: String(stdout ?? ''),
        stderr: String(stderr ?? ''),
        code: Number.isFinite(code) ? code : 1,
      });
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

  /**
   * Optional override that lets an adapter mark itself as SKIPPED without throwing.
   * This is critical for Cisco "known-configs" when nothing is discovered.
   */
  meta?: {
    status?: EngineExecutionMeta['status']; // ok | skipped | failed | timeout
    errorMessage?: string;
    installHint?: string;
  };
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
  const key = (input || '').toLowerCase();
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

function getVerifyDownloadsMode(config?: CliConfig): VerifyDownloadsMode {
  return (config?.verifyDownloads ?? 'warn') as VerifyDownloadsMode;
}

function sha256File(filePath: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function verificationError(tool: string, reason: string): Error {
  return new Error(`[${tool}] download verification failed: ${reason}`);
}

function handleVerificationFailure(mode: VerifyDownloadsMode, tool: string, reason: string): boolean {
  if (mode === 'off') return true;
  if (mode === 'warn') {
    console.warn(`[mergesafe] WARNING: ${tool} verification issue: ${reason}`);
    return true;
  }
  throw verificationError(tool, reason);
}

export function verifyFileWithMode(args: {
  mode: VerifyDownloadsMode;
  tool: ToolName;
  filePath: string;
  expectedSha256?: string;
}): boolean {
  if (args.mode === 'off') return true;
  if (!args.expectedSha256) return handleVerificationFailure(args.mode, args.tool, `missing checksum entry for ${path.basename(args.filePath)}`);
  const actual = sha256File(args.filePath);
  if (actual !== args.expectedSha256) {
    return handleVerificationFailure(args.mode, args.tool, `checksum mismatch for ${path.basename(args.filePath)} (expected ${args.expectedSha256}, got ${actual})`);
  }
  return true;
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
    return stdout
      .split(/\r?\n/)
      .map((x) => x.trim())
      .find(Boolean);
  } catch {
    return undefined;
  }
}

function toPosixPath(p: string): string {
  return String(p || '').replace(/\\/g, '/');
}

/**
 * Normalize a path for findings:
 * - prefer repo/scan-root relative paths for determinism (reproducible reports across machines)
 * - fall back to absolute only when the file is outside the scanRoot
 */
function normalizePathForFinding(filePath: string, scanRoot?: string): string {
  const v = String(filePath || '').trim();
  if (!v) return '';

  const abs = path.isAbsolute(v) ? v : path.resolve(process.cwd(), v);
  const absNorm = path.normalize(abs);

  if (scanRoot) {
    const rootAbs = path.resolve(scanRoot);
    const rootNorm = path.normalize(rootAbs);
    const rel = path.relative(rootNorm, absNorm);

    // If inside scanRoot, use relative path (stable across hosts)
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
      return toPosixPath(rel);
    }

    // If absNorm equals rootNorm (edge), keep a stable token
    if (!rel) return '.';
  }

  // otherwise fall back to absolute (still posix for rendering)
  return toPosixPath(absNorm);
}

function normalizeKeyText(input: string): string {
  return String(input || '')
    .toLowerCase()
    .replace(/[`"'’]/g, '')
    .replace(/[^\p{L}\p{N}\s._-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function uniqueLower(tags: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const t of tags) {
    const v = normalizeKeyText(t);
    if (!v) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

/**
 * Canonicalize category so different engines still merge.
 * (This is the big reason duplicates happen: category differs, merge key differs.)
 */
function canonicalCategory(input: string | undefined, codes: string[]): string {
  const c = normalizeKeyText(input || '');

  // Prefer signal-derived bucket
  if (codes.includes('exec')) return 'injection';
  if (codes.includes('fs-read') || codes.includes('fs-write') || codes.includes('fs')) return 'filesystem';
  if (codes.includes('net-egress')) return 'network';
  if (codes.includes('secrets')) return 'secrets';
  if (codes.includes('gating') || codes.includes('gating-missing') || codes.includes('auth')) return 'auth';
  if (codes.includes('dependencies')) return 'dependencies';

  // Normalize common variants
  if (c.includes('command') || c.includes('injection')) return 'injection';
  if (c.includes('filesystem') || c.includes('file')) return 'filesystem';
  if (c.includes('network') || c.includes('egress') || c.includes('ssrf')) return 'network';
  if (c.includes('secret') || c.includes('token') || c.includes('credential')) return 'secrets';
  if (c.includes('depend') || c.includes('vuln')) return 'dependencies';
  if (c.includes('auth') || c.includes('access')) return 'auth';

  return input ? String(input) : 'mcp-security';
}

function inferSignalCodes(args: {
  engineId: string;
  engineRuleId?: string;
  category?: string;
  title: string;
  message: string;
  tags?: string[];
}): string[] {
  const codes = new Set<string>();

  const engineRuleId = String(args.engineRuleId || '').trim();
  const title = normalizeKeyText(args.title);
  const message = normalizeKeyText(args.message);
  const category = normalizeKeyText(args.category || '');
  const tags = uniqueLower(args.tags ?? []);

  const addIf = (cond: boolean, code: string) => {
    if (cond) codes.add(code);
  };

  // 1) Hard map deterministic MS rules → stable codes
  if (/^MS\d{3}$/i.test(engineRuleId)) {
    const rid = engineRuleId.toUpperCase();
    if (rid === 'MS012') codes.add('exec');
    if (rid === 'MS013') codes.add('fs-read');
    if (rid === 'MS019') codes.add('fs-write');
    if (rid === 'MS014') codes.add('net-egress');
    if (rid === 'MS015') codes.add('secrets');
    if (rid === 'MS016') codes.add('gating-missing');
    if (rid === 'MS009') codes.add('metadata-mismatch');
    if (rid === 'MS017') codes.add('manifest-parse-fail');
    if (rid === 'MS018') codes.add('manifest-empty');
  }

  // 2) Tag-derived codes (preferred)
  addIf(tags.includes('exec') || tags.includes('command-exec') || tags.includes('rce'), 'exec');
  addIf(tags.includes('fs-write') || tags.includes('file-write'), 'fs-write');
  addIf(tags.includes('fs-read') || tags.includes('file-read'), 'fs-read');
  addIf(tags.includes('net-egress') || tags.includes('egress') || tags.includes('http') || tags.includes('fetch'), 'net-egress');
  addIf(tags.includes('secrets') || tags.includes('secret') || tags.includes('token') || tags.includes('apikey') || tags.includes('api_key'), 'secrets');
  addIf(tags.includes('dependencies') || tags.includes('dependency') || tags.includes('vuln') || tags.includes('vulnerability'), 'dependencies');
  addIf(tags.includes('gating') || tags.includes('auth') || tags.includes('allowlist') || tags.includes('confirm'), 'gating');

  // 3) Id/message/title inference
  const idText = normalizeKeyText(engineRuleId);
  addIf(idText.includes('command-exec') || idText.includes('exec') || idText.includes('child_process'), 'exec');
  addIf(idText.includes('file-read') || idText.includes('read-file') || idText.includes('fs-read'), 'fs-read');
  addIf(idText.includes('file-write') || idText.includes('write-file') || idText.includes('fs-write'), 'fs-write');
  addIf(idText.includes('net-egress') || idText.includes('http') || idText.includes('fetch'), 'net-egress');
  addIf(idText.includes('secret') || idText.includes('token') || idText.includes('apikey') || idText.includes('api_key'), 'secrets');

  // 4) Title/message/category inference (fallback)
  addIf(category.includes('secrets'), 'secrets');
  addIf(category.includes('filesystem'), 'fs');
  addIf(category.includes('network'), 'net-egress');
  addIf(category.includes('dependencies'), 'dependencies');
  addIf(category.includes('injection') && (title.includes('command') || message.includes('command') || title.includes('exec')), 'exec');

  // gating/mismatch/manifest integrity
  addIf(title.includes('without allowlist') || title.includes('without gating') || title.includes('without approval'), 'gating-missing');
  addIf(title.includes('read-only') && (title.includes('suggests') || title.includes('conflict') || title.includes('exec') || title.includes('egress') || title.includes('write')), 'metadata-mismatch');
  addIf(title.includes('could not be parsed') || title.includes('failed to parse'), 'manifest-parse-fail');
  addIf(title.includes('contains zero tools') || title.includes('zero tools'), 'manifest-empty');

  if (codes.has('fs') && (codes.has('fs-read') || codes.has('fs-write'))) codes.delete('fs');

  if (codes.size === 0) {
    const fallback = `${category || 'uncat'}:${normalizeKeyText(args.title || args.message).slice(0, 80)}`;
    codes.add(fallback);
  }

  return Array.from(codes).sort();
}

function inferOwaspFromCodes(codes: string[], category?: string): string | undefined {
  const cat = normalizeKeyText(category || '');
  if (codes.includes('secrets')) return 'MCP-A02';
  if (codes.includes('exec')) return 'MCP-A03';
  if (codes.includes('fs-read') || codes.includes('fs-write')) return 'MCP-A04';
  if (codes.includes('net-egress')) return 'MCP-A06';
  if (codes.includes('gating-missing')) return 'MCP-A01';
  if (codes.includes('manifest-parse-fail') || codes.includes('manifest-empty') || codes.includes('metadata-mismatch')) return 'MCP-A09';
  if (cat.includes('dependencies') || codes.includes('dependencies')) return 'MCP-A08';
  return undefined;
}

/**
 * Canonicalizes an engine finding into MergeSafe's shared Finding shape.
 * Key fixes:
 * - engine-neutral fingerprinting (signal codes only)
 * - normalize category to avoid cross-engine duplicate rows
 * - keep engineSources so report can show "Found by"
 * - repo/scan-root relative paths for deterministic output
 */
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
  owaspMcpTop10?: string;
  tags?: string[];
  scanRoot?: string;
}): Finding {
  const normFilePath = normalizePathForFinding(args.filePath, args.scanRoot);

  const tagsLower = uniqueLower([...(args.tags ?? [])]);
  // keep engineId as a tag for display if you want; core/report can ignore it
  const mergedTags = Array.from(new Set([normalizeKeyText(args.engineId), ...tagsLower])).filter(Boolean);

  const codes = inferSignalCodes({
    engineId: args.engineId,
    engineRuleId: args.engineRuleId,
    category: args.category,
    title: args.title,
    message: args.message,
    tags: mergedTags,
  });

  const signalKey = codes.join('|');
  const fingerprint = findingFingerprint(normFilePath, args.line, signalKey);

  const evidenceHashMaterial = args.evidence?.trim()
    ? args.evidence
    : `${String(args.engineRuleId ?? '').trim()}:${normalizeKeyText(args.message || args.title)}`;
  const excerptHash = stableHash(evidenceHashMaterial);

  const owasp = args.owaspMcpTop10 ?? inferOwaspFromCodes(codes, args.category) ?? 'MCP-A10';
  const category = canonicalCategory(args.category, codes);

  // add canonical tags for merge friendliness (helps family inference in core)
  const canonicalTags = new Set<string>(mergedTags);
  for (const c of codes) {
    if (
      c === 'exec' ||
      c === 'fs-read' ||
      c === 'fs-write' ||
      c === 'net-egress' ||
      c === 'secrets' ||
      c === 'dependencies' ||
      c === 'gating-missing'
    ) {
      canonicalTags.add(c);
    }
  }

  return {
    findingId: `ms-${fingerprint}`, // engine-neutral
    title: args.title,
    severity: normalizeSeverity(args.engineSeverity ?? 'medium'),
    confidence: args.confidence ?? 'medium',
    category,
    owaspMcpTop10: owasp,
    engineSources: [
      {
        engineId: args.engineId,
        engineRuleId: args.engineRuleId,
        engineSeverity: args.engineSeverity,
        message: args.message,
      },
    ],
    locations: [{ filePath: normFilePath, line: Math.max(1, Number(args.line ?? 1)) }],
    evidence: args.evidence?.trim()
      ? { excerpt: args.evidence, note: 'Engine finding evidence' }
      : { excerptHash, note: 'Evidence hash only (redacted or unavailable)' },
    remediation: args.remediation ?? 'Review and remediate based on engine guidance.',
    references: [],
    tags: Array.from(canonicalTags).filter(Boolean),
    fingerprint,
  };
}

function engineArtifactBase(ctx: EngineContext, engineId: string): string {
  const outDir = path.resolve(ctx.config.outDir || 'mergesafe');
  const dir = path.join(outDir, 'artifacts', engineId);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function normalizePathForScan(scanPath: string, p: string): string {
  const v = String(p || '').trim();
  if (!v) return normalizePathForFinding(path.resolve(scanPath, 'unknown'), scanPath);
  const abs = path.isAbsolute(v) ? v : path.resolve(scanPath, v);
  return normalizePathForFinding(abs, scanPath);
}

export function getToolsDir(): string {
  const root = path.resolve(process.env.MERGESAFE_TOOLS_DIR || path.join(os.homedir(), '.mergesafe', 'tools'));
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
    try {
      data = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      data = {};
    }
  }
  data[tool] = { version, binaryPath, installedAt: new Date().toISOString() };
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function venvBinDir(venvDir: string): string {
  return process.platform === 'win32' ? path.join(venvDir, 'Scripts') : path.join(venvDir, 'bin');
}

function venvPythonExecutable(venvDir: string): string {
  const bin = venvBinDir(venvDir);
  return process.platform === 'win32' ? path.join(bin, 'python.exe') : path.join(bin, 'python');
}

async function venvPipInstall(
  venvDir: string,
  args: string[],
  opts: Parameters<typeof execFile>[2] = {}
): Promise<void> {
  const py = venvPythonExecutable(venvDir);
  await execFilePromise(py, ['-m', 'pip', ...args], opts);
}

function semgrepExecutable(venvDir: string): string {
  const bin = venvBinDir(venvDir);
  const candidates = process.platform === 'win32' ? ['semgrep.exe', 'semgrep'] : ['semgrep'];
  for (const c of candidates) {
    const p = path.join(bin, c);
    if (fs.existsSync(p)) return p;
  }
  return process.platform === 'win32' ? path.join(bin, 'semgrep.exe') : path.join(bin, 'semgrep');
}

function ciscoExecutable(venvDir: string): string {
  const bin = venvBinDir(venvDir);
  const candidates =
    process.platform === 'win32'
      ? ['mcp-scanner.exe', 'mcp_scanner.exe', 'mcp-scanner', 'mcp_scanner']
      : ['mcp-scanner', 'mcp_scanner'];

  for (const c of candidates) {
    const p = path.join(bin, c);
    if (fs.existsSync(p)) return p;
  }

  return process.platform === 'win32' ? path.join(bin, 'mcp-scanner.exe') : path.join(bin, 'mcp-scanner');
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

function githubHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.MERGESAFE_GITHUB_TOKEN;
  const headers: Record<string, string> = {
    'User-Agent': 'mergesafe-scanner',
    Accept: 'application/vnd.github+json',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function downloadFile(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) throw new Error(`Failed download ${url}: ${res.status}`);
  await fs.promises.mkdir(path.dirname(dest), { recursive: true });
  await fs.promises.writeFile(dest, Buffer.from(await res.arrayBuffer()));
}

function cachedBinary(tool: ToolName, versionTag: string, exe: string): string {
  return path.join(getToolsDir(), 'bin', tool, versionTag, exe);
}

export function existingBinary(tool: ToolName, verifyMode: VerifyDownloadsMode): string | undefined {
  const manifest = TOOL_MANIFEST[tool];
  const artifact = resolveToolArtifact(tool);
  if (!artifact) return undefined;
  const target = cachedBinary(tool, manifest.version, artifact.binaryName);
  if (!fs.existsSync(target)) return undefined;
  verifyFileWithMode({ mode: verifyMode, tool, filePath: target, expectedSha256: artifact.sha256 });
  return target;
}

export async function ensureManifestBinary(tool: ToolName, verifyMode: VerifyDownloadsMode): Promise<string> {
  const manifest = TOOL_MANIFEST[tool];
  const artifact = resolveToolArtifact(tool);
  if (!artifact) throw new Error(`No ${tool} artifact configured for ${process.platform}/${process.arch}`);

  const target = cachedBinary(tool, manifest.version, artifact.binaryName);
  if (fs.existsSync(target)) {
    verifyFileWithMode({ mode: verifyMode, tool, filePath: target, expectedSha256: artifact.sha256 });
    return target;
  }

  const baseDir = path.join(getToolsDir(), 'downloads', tool, manifest.version);
  const archiveName = path.basename(new URL(artifact.url).pathname);
  const archivePath = path.join(baseDir, archiveName || `${tool}-${manifest.version}`);
  const extractDir = path.join(baseDir, 'extract');

  if (!fs.existsSync(archivePath)) {
    await downloadFile(artifact.url, archivePath);
  }
  verifyFileWithMode({ mode: verifyMode, tool, filePath: archivePath, expectedSha256: artifact.sha256 });

  fs.rmSync(extractDir, { recursive: true, force: true });
  fs.mkdirSync(extractDir, { recursive: true });

  if (artifact.archiveType === 'zip') {
    if (process.platform === 'win32') {
      await execFilePromise('powershell.exe', [
        '-NoProfile',
        '-Command',
        `Expand-Archive -Path "${archivePath}" -DestinationPath "${extractDir}" -Force`,
      ]);
    } else {
      await execFilePromise('unzip', ['-o', archivePath, '-d', extractDir]);
    }
  } else if (artifact.archiveType === 'tar.gz') {
    await execFilePromise(process.platform === 'win32' ? 'tar.exe' : 'tar', ['-xzf', archivePath, '-C', extractDir]);
  } else {
    fs.copyFileSync(archivePath, path.join(extractDir, artifact.binaryName));
  }

  const discovered = findFileRecursive(extractDir, (name) => name.toLowerCase() === artifact.binaryName.toLowerCase());
  if (!discovered) throw new Error(`Downloaded ${tool} archive did not contain expected binary ${artifact.binaryName}`);

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(discovered, target);
  if (process.platform !== 'win32') fs.chmodSync(target, 0o755);

  verifyFileWithMode({ mode: verifyMode, tool, filePath: target, expectedSha256: artifact.sha256 });
  updateToolsManifest(tool, manifest.version, target);
  return target;
}

function resolvePythonCommand(): Promise<string | undefined> {
  return (async () => {
    for (const candidate of process.platform === 'win32' ? ['py', 'python', 'python3'] : ['python3', 'python']) {
      if (await hasBinary(candidate)) return candidate;
    }
    return undefined;
  })();
}

export async function ensureSemgrepBinary(verifyMode: VerifyDownloadsMode): Promise<string> {
  const venvDir = path.join(getToolsDir(), 'venvs', 'semgrep');
  const existing = semgrepExecutable(venvDir);
  if (fs.existsSync(existing)) return existing;

  const python = await resolvePythonCommand();
  if (!python) throw new Error('Python is required to auto-install semgrep.');

  await execFilePromise(python, ['-m', 'venv', venvDir]);

  const manifest = TOOL_MANIFEST.semgrep;
  const artifact = resolveToolArtifact('semgrep');
  if (!artifact) throw new Error(`No semgrep artifact configured for ${process.platform}/${process.arch}`);

  const wheelDir = path.join(getToolsDir(), 'downloads', 'semgrep', manifest.version);
  const wheelPath = path.join(wheelDir, path.basename(new URL(artifact.url).pathname));
  if (!fs.existsSync(wheelPath)) {
    await downloadFile(artifact.url, wheelPath);
  }
  verifyFileWithMode({ mode: verifyMode, tool: 'semgrep', filePath: wheelPath, expectedSha256: artifact.sha256 });

  await venvPipInstall(venvDir, ['install', '--upgrade', 'pip', 'setuptools', 'wheel'], {
    maxBuffer: 20 * 1024 * 1024,
  });
  await venvPipInstall(venvDir, ['install', '--upgrade', wheelPath], { maxBuffer: 40 * 1024 * 1024 });

  const bin = semgrepExecutable(venvDir);
  if (!fs.existsSync(bin)) throw new Error('Semgrep install completed but executable was not found in venv.');
  if (process.platform !== 'win32') fs.chmodSync(bin, 0o755);

  updateToolsManifest('semgrep', manifest.version, bin);
  return bin;
}

function isPipNoDistribution(msg: string): boolean {
  const m = (msg || '').toLowerCase();
  return m.includes('no matching distribution found') || m.includes('could not find a version that satisfies');
}

async function ensureCiscoBinary(): Promise<string> {
  const venvDir = path.join(getToolsDir(), 'venvs', 'cisco-mcp-scanner');
  const existing = ciscoExecutable(venvDir);
  if (fs.existsSync(existing)) return existing;

  const python = await resolvePythonCommand();
  if (!python) throw new Error('Python is required to auto-install cisco mcp-scanner.');

  await execFilePromise(python, ['-m', 'venv', venvDir]);

  const pkgBase = 'cisco-ai-mcp-scanner';
  const pkgSpec = process.env.MERGESAFE_CISCO_VERSION ? `${pkgBase}==${process.env.MERGESAFE_CISCO_VERSION}` : pkgBase;

  await venvPipInstall(venvDir, ['install', '--upgrade', 'pip', 'setuptools', 'wheel'], {
    maxBuffer: 20 * 1024 * 1024,
  });
  await venvPipInstall(venvDir, ['install', '--upgrade', pkgSpec], { maxBuffer: 40 * 1024 * 1024 });

  const bin = ciscoExecutable(venvDir);
  if (!fs.existsSync(bin)) throw new Error('Cisco mcp-scanner install completed but executable was not found in venv.');
  if (process.platform !== 'win32') fs.chmodSync(bin, 0o755);

  updateToolsManifest('cisco', process.env.MERGESAFE_CISCO_VERSION || 'unpinned', bin);
  return bin;
}

function withTimeout<T>(promise: Promise<T>, timeoutSec: number, timeoutError: Error): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(timeoutError), Math.max(timeoutSec, 1) * 1000);
    promise
      .then((r) => {
        clearTimeout(timer);
        resolve(r);
      })
      .catch((e) => {
        clearTimeout(timer);
        reject(e);
      });
  });
}

export class MergeSafeAdapter implements EngineAdapter {
  engineId = 'mergesafe';
  displayName = 'MergeSafe deterministic rules';
  installHint = 'Built in - no install required.';
  async version() {
    return 'builtin';
  }
  async isAvailable() {
    return true;
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    const { findings: raw } = runDeterministicRules(ctx.scanPath, ctx.config.mode);
    return raw.map((entry) => {
      // Keep tags/owasp if provided, but also ensure category aligns cross-engine
      const tags = Array.isArray((entry as any).tags) ? (entry as any).tags : [];
      const codes = inferSignalCodes({
        engineId: this.engineId,
        engineRuleId: entry.ruleId,
        category: entry.category,
        title: entry.title,
        message: entry.title,
        tags,
      });
      const cat = canonicalCategory(entry.category, codes);

      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: entry.ruleId,
        engineSeverity: entry.severity,
        message: entry.title,
        title: entry.title,
        filePath: path.resolve(ctx.scanPath, entry.filePath),
        line: entry.line,
        evidence: ctx.config.redact ? '' : entry.evidence,
        confidence: entry.confidence,
        category: cat,
        remediation: entry.remediation,
        owaspMcpTop10: (entry as any).owaspMcpTop10,
        tags,
        scanRoot: ctx.scanPath,
      });
    });
  }
}

function inferSemgrepMeta(checkId: string, message: string): { tags: string[]; category?: string; owasp?: string } {
  const id = normalizeKeyText(checkId);
  const msg = normalizeKeyText(message);
  const tags = new Set<string>();
  const add = (t: string) => tags.add(t);

  if (id.includes('command-exec') || id.includes('child_process') || id.includes('exec') || msg.includes('command execution')) {
    add('exec');
    add('policy');
    return { tags: Array.from(tags), category: 'injection', owasp: 'MCP-A03' };
  }

  if (id.includes('file-write') || id.includes('fs-write') || msg.includes('file write')) {
    add('fs-write');
    add('policy');
    return { tags: Array.from(tags), category: 'filesystem', owasp: 'MCP-A04' };
  }

  if (id.includes('file-read') || id.includes('fs-read') || msg.includes('file read') || msg.includes('read file')) {
    add('fs-read');
    add('policy');
    return { tags: Array.from(tags), category: 'filesystem', owasp: 'MCP-A04' };
  }

  if (id.includes('net-egress') || id.includes('http') || id.includes('fetch') || msg.includes('network egress') || msg.includes('fetch')) {
    add('net-egress');
    add('policy');
    return { tags: Array.from(tags), category: 'network', owasp: 'MCP-A06' };
  }

  if (id.includes('secret') || id.includes('token') || id.includes('apikey') || id.includes('api_key') || msg.includes('secret')) {
    add('secrets');
    add('policy');
    return { tags: Array.from(tags), category: 'secrets', owasp: 'MCP-A02' };
  }

  add('semgrep');
  return { tags: Array.from(tags) };
}

export class SemgrepAdapter implements EngineAdapter {
  engineId = 'semgrep';
  displayName = 'Semgrep (local rules only)';
  installHint = 'Auto-install semgrep into MergeSafe tools cache or install semgrep manually.';
  private resolvedBinary?: string;

  private async resolveBinary(ctx?: EngineContext) {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary =
      existingBinary('semgrep', getVerifyDownloadsMode(ctx?.config)) ||
      (await resolvePathBinary('semgrep')) ||
      semgrepExecutable(path.join(getToolsDir(), 'venvs', 'semgrep'));
    return this.resolvedBinary && fs.existsSync(this.resolvedBinary) ? this.resolvedBinary : undefined;
  }

  async ensureAvailable(ctx: EngineContext) {
    this.resolvedBinary = await ensureSemgrepBinary(getVerifyDownloadsMode(ctx.config));
  }

  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['--version']);
    return stdout.trim() || 'unknown';
  }

  async isAvailable(ctx: EngineContext) {
    return Boolean(await this.resolveBinary(ctx));
  }

  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary(ctx);
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);

    const here = path.dirname(fileURLToPath(import.meta.url));
    const configPath = path.resolve(here, '../semgrep-rules/entry.yml');
    if (!fs.existsSync(configPath)) {
      throw new Error(`Semgrep config not found at ${configPath}. Did you create semgrep-rules/entry.yml ?`);
    }

    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');

    const env = {
      ...process.env,
      SEMGREP_SEND_METRICS: 'off',
      PYTHONUTF8: '1',
      PYTHONIOENCODING: 'utf-8',
    };

    const runJson = await execFileAllowFailure(
      bin,
      ['--config', configPath, '--json', '--output', jsonPath, ctx.scanPath],
      { maxBuffer: 30 * 1024 * 1024, env }
    );

    if (!fs.existsSync(jsonPath)) {
      throw new Error(`Semgrep did not write results.json (exit=${runJson.code}). ${String(runJson.stderr || runJson.stdout).trim()}`);
    }

    const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as any;

    const errors = Array.isArray(parsed?.errors) ? parsed.errors : [];
    if (errors.length) {
      const e0 = errors[0] ?? {};
      const span0 = Array.isArray(e0.spans) && e0.spans[0] ? e0.spans[0] : undefined;
      const where = span0?.file ? `${span0.file}:${span0.start?.line ?? 1}` : '';
      const msg = String(e0.short_msg || e0.message || e0.long_msg || 'Semgrep config error');
      throw new Error(`Semgrep config error: ${msg}${where ? ` (${where})` : ''}`);
    }

    await execFileAllowFailure(bin, ['--config', configPath, '--sarif', '--output', sarifPath, ctx.scanPath], {
      maxBuffer: 30 * 1024 * 1024,
      env,
    });

    const results = Array.isArray(parsed?.results) ? parsed.results : [];
    const findings = results.map((item: any) => {
      const extra = (item.extra ?? {}) as Record<string, any>;
      const start = (item.start ?? {}) as Record<string, any>;

      const checkId = String(item.check_id ?? 'semgrep.rule');
      const msg = String(extra.message ?? item.path ?? 'Semgrep finding');
      const meta = inferSemgrepMeta(checkId, msg);

      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: checkId,
        engineSeverity: String(extra.severity ?? 'INFO'),
        message: msg,
        title: String(extra.message ?? 'Semgrep finding'),
        filePath: path.resolve(ctx.scanPath, String(item.path ?? 'unknown')),
        line: Number(start.line ?? 1),
        evidence: ctx.config.redact ? '' : String(extra.lines ?? '').trim(),
        category: meta.category,
        owaspMcpTop10: meta.owasp,
        tags: meta.tags,
        scanRoot: ctx.scanPath,
      });
    });

    return {
      findings,
      artifacts: { json: jsonPath, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined },
    };
  }
}

export class GitleaksAdapter implements EngineAdapter {
  engineId = 'gitleaks';
  displayName = 'Gitleaks';
  installHint = 'Auto-install gitleaks into MergeSafe tools cache or install gitleaks manually.';
  private resolvedBinary?: string;

  private async resolveBinary(ctx?: EngineContext) {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary =
      existingBinary('gitleaks', getVerifyDownloadsMode(ctx?.config)) ||
      (await resolvePathBinary('gitleaks'));
    return this.resolvedBinary;
  }

  async ensureAvailable(ctx: EngineContext) {
    this.resolvedBinary = await ensureManifestBinary('gitleaks', getVerifyDownloadsMode(ctx.config));
  }

  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['version']);
    return stdout.trim() || 'unknown';
  }

  async isAvailable(ctx: EngineContext) {
    return Boolean(await this.resolveBinary(ctx));
  }

  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary(ctx);
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);

    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');

    await execFileAllowFailure(bin, [
      'detect',
      '--source',
      ctx.scanPath,
      '--redact',
      '--report-format',
      'json',
      '--report-path',
      jsonPath,
    ]);
    await execFileAllowFailure(bin, [
      'detect',
      '--source',
      ctx.scanPath,
      '--redact',
      '--report-format',
      'sarif',
      '--report-path',
      sarifPath,
    ]);

    if (!fs.existsSync(jsonPath)) {
      return { findings: [], artifacts: { sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
    }

    const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as Array<Record<string, any>>;
    const findings = parsed.map((item) =>
      canonicalFinding({
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
        tags: ['secrets'],
        owaspMcpTop10: 'MCP-A02',
        scanRoot: ctx.scanPath,
      })
    );

    return { findings, artifacts: { json: jsonPath, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
  }
}

function getCiscoConfig(ctx: EngineContext): CiscoConfig {
  return ((ctx.config as any)?.cisco ?? {}) as CiscoConfig;
}

function isCiscoNoTargetsOutput(text: string): boolean {
  const t = (text || '').toLowerCase();
  return (
    t.includes('no known config') ||
    t.includes('no known configs') ||
    t.includes('no configs found') ||
    t.includes('no configuration found') ||
    t.includes('no mcp config') ||
    t.includes('no mcp configs') ||
    t.includes('no servers found') ||
    t.includes('0 server') ||
    t.includes('0 servers')
  );
}

function isCiscoUnrecognizedArg(text: string): boolean {
  const t = (text || '').toLowerCase();
  return t.includes('unrecognized arguments') || t.includes('unknown option') || t.includes('unknown arguments');
}

function resolveMaybePathWithBase(p: string, baseDir: string): string {
  const v = String(p || '').trim();
  if (!v) return '';
  if (path.isAbsolute(v)) return v;

  const relToScan = path.resolve(baseDir, v);
  if (fs.existsSync(relToScan)) return relToScan;

  return path.resolve(process.cwd(), v);
}

const REPO_TOOLS_MANIFEST_BASENAMES = ['tools-list.json', 'tools.json', 'mcp-tools.json'];

function discoverRepoToolsList(scanPath: string): string | undefined {
  for (const base of REPO_TOOLS_MANIFEST_BASENAMES) {
    const candidate = path.join(scanPath, base);
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // ignore
    }
  }

  try {
    const entries = fs.readdirSync(scanPath, { withFileTypes: true });
    for (const e of entries) {
      if (!e.isFile()) continue;
      const name = e.name.toLowerCase();
      if (!name.endsWith('.json')) continue;
      if (
        name.includes('tools') &&
        (name.includes('mcp') || name.includes('tool')) &&
        !name.includes('package-lock') &&
        !name.includes('pnpm-lock')
      ) {
        return path.join(scanPath, e.name);
      }
    }
  } catch {
    // ignore
  }

  return undefined;
}

function extractLikelyJson(text: string): string | undefined {
  const t = String(text || '').trim();
  if (!t) return undefined;

  try {
    JSON.parse(t);
    return t;
  } catch {
    // ignore
  }

  const candidates: string[] = [];
  const o1 = t.indexOf('{');
  const o2 = t.lastIndexOf('}');
  if (o1 !== -1 && o2 > o1) candidates.push(t.slice(o1, o2 + 1));

  const a1 = t.indexOf('[');
  const a2 = t.lastIndexOf(']');
  if (a1 !== -1 && a2 > a1) candidates.push(t.slice(a1, a2 + 1));

  for (const c of candidates) {
    try {
      JSON.parse(c);
      return c;
    } catch {
      // ignore
    }
  }
  return undefined;
}

export class CiscoMcpAdapter implements EngineAdapter {
  engineId = 'cisco';
  displayName = 'Cisco mcp-scanner (offline-safe)';
  installHint = 'Auto-install cisco-ai-mcp-scanner into MergeSafe tools cache or install it manually (CLI: mcp-scanner).';
  private resolvedBinary?: string;

  private async resolveBinary(ctx?: EngineContext) {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary = ciscoExecutable(path.join(getToolsDir(), 'venvs', 'cisco-mcp-scanner'));
    if (!fs.existsSync(this.resolvedBinary)) this.resolvedBinary = await resolvePathBinary('mcp-scanner');
    return this.resolvedBinary;
  }

  async ensureAvailable() {
    this.resolvedBinary = await ensureCiscoBinary();
  }

  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    return 'unknown';
  }

  async isAvailable(ctx: EngineContext) {
    return Boolean(await this.resolveBinary(ctx));
  }

  private buildBaseArgs(cfg: CiscoConfig, jsonPath: string): string[] {
    const analyzers = (cfg.analyzers ?? 'yara').trim() || 'yara';
    const args: string[] = ['--analyzers', analyzers, '--format', 'raw', '--output', jsonPath];

    if (cfg.bearerToken) args.push('--bearer-token', cfg.bearerToken);
    for (const h of cfg.headers ?? []) {
      const hv = String(h || '').trim();
      if (hv) args.push('--header', hv);
    }

    return args;
  }

  private parseCiscoFindings(ctx: EngineContext, raw: any): Finding[] {
    const list: any[] =
      Array.isArray(raw)
        ? raw
        : Array.isArray(raw?.findings)
          ? raw.findings
          : Array.isArray(raw?.issues)
            ? raw.issues
            : Array.isArray(raw?.results)
              ? raw.results
              : Array.isArray(raw?.data)
                ? raw.data
                : [];

    return list.map((item: any) =>
      canonicalFinding({
        engineId: this.engineId,
        engineRuleId: String(item.rule_id ?? item.ruleId ?? item.id ?? 'cisco.mcp'),
        engineSeverity: String(item.severity ?? item.level ?? item.priority ?? 'medium'),
        message: String(item.message ?? item.title ?? 'Cisco MCP finding'),
        title: String(item.title ?? item.message ?? 'Cisco MCP finding'),
        filePath: path.resolve(ctx.scanPath, String(item.file ?? item.path ?? '__cisco__')),
        line: Number(item.line ?? item.start_line ?? item.startLine ?? 1),
        evidence: ctx.config.redact ? '' : String(item.snippet ?? item.evidence ?? item.details ?? ''),
        tags: ['cisco'],
        scanRoot: ctx.scanPath,
      })
    );
  }

  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary(ctx);
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);

    const cfg = getCiscoConfig(ctx);
    if (cfg.enabled === false) {
      return { findings: [], meta: { status: 'skipped', errorMessage: 'Cisco disabled by config.' } };
    }

    const repoTools = discoverRepoToolsList(ctx.scanPath);
    const explicitMode = (cfg.mode ?? 'auto') as CiscoMode;

    const resolvedToolsPath = cfg.toolsPath
      ? resolveMaybePathWithBase(cfg.toolsPath, ctx.scanPath)
      : repoTools
        ? path.resolve(repoTools)
        : '';

    const mode: CiscoMode = explicitMode === 'auto' ? (resolvedToolsPath ? 'static' : 'known-configs') : explicitMode;

    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');

    const baseArgs = this.buildBaseArgs(cfg, jsonPath);
    const env = { ...process.env, MCP_SCANNER_OFFLINE: '1' };

    const runAndMaterializeOutput = async (
      args: string[],
      skipHintIfEmpty: string
    ): Promise<{ ran: boolean; skipped?: string; stdout: string; stderr: string; code: number }> => {
      if (fs.existsSync(jsonPath)) {
        try {
          fs.unlinkSync(jsonPath);
        } catch {
          // ignore
        }
      }

      const last = await execFileAllowFailure(bin, args, { maxBuffer: 40 * 1024 * 1024, env });

      // Prefer file output if it exists
      if (fs.existsSync(jsonPath)) return { ran: true, stdout: last.stdout, stderr: last.stderr, code: last.code };

      const combined = `${last.stdout}\n${last.stderr}`.trim();

      // If Cisco printed JSON but didn't write the file, capture it
      const jsonPayload = extractLikelyJson(combined);
      if (jsonPayload) {
        try {
          fs.writeFileSync(jsonPath, jsonPayload, 'utf8');
          return { ran: true, stdout: last.stdout, stderr: last.stderr, code: last.code };
        } catch {
          // fall through
        }
      }

      if (!combined) return { ran: false, skipped: skipHintIfEmpty, stdout: last.stdout, stderr: last.stderr, code: last.code };

      if (isCiscoNoTargetsOutput(combined)) {
        return { ran: false, skipped: skipHintIfEmpty, stdout: last.stdout, stderr: last.stderr, code: last.code };
      }

      throw new Error(`Cisco failed (no output file produced). ${combined}`);
    };

    if (mode === 'static') {
      if (!resolvedToolsPath) {
        return {
          findings: [],
          meta: {
            status: 'skipped',
            errorMessage:
              'Cisco static mode requires tools JSON. Put tools-list.json/tools.json/mcp-tools.json in the scan folder or provide --cisco-tools <path>.',
            installHint: this.installHint,
          },
        };
      }
      if (!fs.existsSync(resolvedToolsPath)) {
        return {
          findings: [],
          meta: {
            status: 'skipped',
            errorMessage: `Cisco static mode: tools JSON not found at ${resolvedToolsPath}.`,
            installHint: this.installHint,
          },
        };
      }

      const res = await runAndMaterializeOutput(
        [...baseArgs, 'static', '--tools', resolvedToolsPath],
        'Cisco static produced no output.'
      );
      if (!res.ran) throw new Error(res.skipped || 'Cisco static produced no output.');
    } else if (mode === 'known-configs') {
      const attempt1 = await runAndMaterializeOutput(
        [...baseArgs, '--scan-known-configs'],
        'No MCP client configs found in known locations.'
      );
      if (!attempt1.ran) {
        const combined = `${attempt1.stdout}\n${attempt1.stderr}`;
        if (isCiscoUnrecognizedArg(combined)) {
          const attempt2 = await runAndMaterializeOutput(
            [...baseArgs, 'known-configs'],
            'No MCP client configs found in known locations.'
          );
          if (!attempt2.ran) {
            return { findings: [], meta: { status: 'skipped', errorMessage: 'No MCP client configs found in known locations.' } };
          }
        } else {
          return { findings: [], meta: { status: 'skipped', errorMessage: 'No MCP client configs found in known locations.' } };
        }
      }
    } else if (mode === 'config') {
      const configPath = cfg.configPath ? resolveMaybePathWithBase(cfg.configPath, ctx.scanPath) : '';
      if (!configPath) {
        return { findings: [], meta: { status: 'skipped', errorMessage: 'Cisco config mode requires --cisco-config-path <path>.' } };
      }
      if (!fs.existsSync(configPath)) {
        return { findings: [], meta: { status: 'skipped', errorMessage: `Cisco config mode: file not found at ${configPath}.` } };
      }
      const res = await runAndMaterializeOutput(
        [...baseArgs, 'config', '--config-path', configPath],
        'Cisco config scan produced no output.'
      );
      if (!res.ran) throw new Error(res.skipped || 'Cisco config scan produced no output.');
    } else if (mode === 'remote') {
      const serverUrl = String(cfg.serverUrl || '').trim();
      if (!serverUrl) {
        return { findings: [], meta: { status: 'skipped', errorMessage: 'Cisco remote mode requires --cisco-server-url <url>.' } };
      }
      const res = await runAndMaterializeOutput(
        [...baseArgs, 'remote', '--server-url', serverUrl],
        'Cisco remote scan produced no output.'
      );
      if (!res.ran) throw new Error(res.skipped || 'Cisco remote scan produced no output.');
    } else if (mode === 'stdio') {
      const cmd = String(cfg.stdioCommand || '').trim();
      if (!cmd) {
        return { findings: [], meta: { status: 'skipped', errorMessage: 'Cisco stdio mode requires --cisco-stdio-command <cmd>.' } };
      }
      const args: string[] = [...baseArgs, 'stdio', '--stdio-command', cmd];
      for (const a of cfg.stdioArgs ?? []) {
        const av = String(a || '').trim();
        if (av) args.push('--stdio-arg', av);
      }
      const res = await runAndMaterializeOutput(args, 'Cisco stdio scan produced no output.');
      if (!res.ran) throw new Error(res.skipped || 'Cisco stdio scan produced no output.');
    }

    if (!fs.existsSync(jsonPath)) {
      return {
        findings: [],
        artifacts: { json: undefined },
        meta: { status: 'skipped', errorMessage: 'Cisco did not produce output.' },
      };
    }

    const content = fs.readFileSync(jsonPath, 'utf8');
    let raw: any = null;
    try {
      raw = JSON.parse(content);
    } catch {
      return {
        findings: [],
        artifacts: { json: jsonPath },
        meta: { status: 'failed', errorMessage: 'Cisco produced output but it was not valid JSON. See artifacts for raw output.' },
      };
    }

    const findings = this.parseCiscoFindings(ctx, raw);
    return {
      findings,
      artifacts: { json: jsonPath },
      meta: { status: 'ok' },
    };
  }
}

export class OsvScannerAdapter implements EngineAdapter {
  engineId = 'osv';
  displayName = 'OSV-Scanner';
  installHint = 'Auto-install osv-scanner into MergeSafe tools cache or install osv-scanner manually.';
  private resolvedBinary?: string;

  private async resolveBinary(ctx?: EngineContext) {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary =
      existingBinary('osv-scanner', getVerifyDownloadsMode(ctx?.config)) ||
      (await resolvePathBinary('osv-scanner'));
    return this.resolvedBinary;
  }

  async ensureAvailable(ctx: EngineContext) {
    this.resolvedBinary = await ensureManifestBinary('osv-scanner', getVerifyDownloadsMode(ctx.config));
  }

  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['--version']);
    return stdout.trim() || 'unknown';
  }

  async isAvailable(ctx: EngineContext) {
    return Boolean(await this.resolveBinary(ctx));
  }

  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary(ctx);
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);

    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');

    await execFileAllowFailure(bin, ['scan', 'source', '-r', ctx.scanPath, '--format', 'json', '--output', jsonPath]);
    await execFileAllowFailure(bin, ['scan', 'source', '-r', ctx.scanPath, '--format', 'sarif', '--output', sarifPath]);

    if (!fs.existsSync(jsonPath)) {
      return { findings: [], artifacts: { sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
    }

    const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as any;
    const vulns = (raw.results ?? []).flatMap(
      (entry: any) => entry.packages?.flatMap((p: any) => p.vulnerabilities ?? []) ?? entry.vulnerabilities ?? []
    );

    const findings: Finding[] = (vulns as any[]).map((v: any) =>
      canonicalFinding({
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
        tags: ['dependencies'],
        owaspMcpTop10: 'MCP-A08',
        scanRoot: ctx.scanPath,
      })
    );

    return { findings, artifacts: { json: jsonPath, sarif: fs.existsSync(sarifPath) ? sarifPath : undefined } };
  }
}

export class TrivyAdapter implements EngineAdapter {
  engineId = 'trivy';
  displayName = 'Trivy';
  installHint = 'Auto-install trivy into MergeSafe tools cache or install trivy manually.';
  private resolvedBinary?: string;

  private async resolveBinary(ctx?: EngineContext) {
    if (this.resolvedBinary && fs.existsSync(this.resolvedBinary)) return this.resolvedBinary;
    this.resolvedBinary =
      existingBinary('trivy', getVerifyDownloadsMode(ctx?.config)) ||
      (await resolvePathBinary('trivy'));
    return this.resolvedBinary;
  }

  async ensureAvailable(ctx: EngineContext) {
    this.resolvedBinary = await ensureManifestBinary('trivy', getVerifyDownloadsMode(ctx.config));
  }

  async version() {
    const bin = await this.resolveBinary();
    if (!bin) return 'unavailable';
    const { stdout } = await execFileAllowFailure(bin, ['--version']);
    return stdout.split('\n')[0]?.trim() || 'unknown';
  }

  async isAvailable(ctx: EngineContext) {
    return Boolean(await this.resolveBinary(ctx));
  }

  async run(ctx: EngineContext): Promise<EngineRunResult> {
    const bin = await this.resolveBinary(ctx);
    if (!bin) throw new Error(`Not installed. ${this.installHint}`);

    const base = engineArtifactBase(ctx, this.engineId);
    const jsonPath = path.join(base, 'results.json');
    const sarifPath = path.join(base, 'results.sarif');

    await execFileAllowFailure(bin, ['fs', '--format', 'json', '--output', jsonPath, ctx.scanPath]);
    await execFileAllowFailure(bin, ['fs', '--format', 'sarif', '--output', sarifPath, ctx.scanPath]);

    return {
      findings: [],
      artifacts: {
        json: fs.existsSync(jsonPath) ? jsonPath : undefined,
        sarif: fs.existsSync(sarifPath) ? sarifPath : undefined,
      },
    };
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
      let version = 'unknown';
      let available = false;

      try {
        version = await adapter.version();
        available = await adapter.isAvailable(ctx);
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error ?? '');
        meta.push({
          engineId: adapter.engineId,
          displayName: adapter.displayName,
          version,
          status: 'failed',
          durationMs: Date.now() - start,
          installHint: adapter.installHint,
          errorMessage: `Preflight failed: ${msg}`,
        });
        continue;
      }

      if (!available && ctx.config.autoInstall && adapter.ensureAvailable) {
        try {
          await adapter.ensureAvailable(ctx);
          available = await adapter.isAvailable(ctx);
          version = await adapter.version();
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error ?? '');
          const markSkipped = adapter.engineId === 'cisco' && isPipNoDistribution(msg);

          meta.push({
            engineId: adapter.engineId,
            displayName: adapter.displayName,
            version,
            status: markSkipped ? 'skipped' : 'failed',
            durationMs: Date.now() - start,
            installHint: adapter.installHint,
            errorMessage: `Auto-install failed: ${msg}`,
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
        const result = await withTimeout(
          adapter.run(ctx),
          ctx.config.timeout,
          new Error(`Timed out after ${ctx.config.timeout}s`)
        );

        const normalized: EngineRunResult = Array.isArray(result) ? { findings: result } : result;
        const status = normalized.meta?.status ?? 'ok';

        if (status === 'ok') findings.push(...normalized.findings);

        meta.push({
          engineId: adapter.engineId,
          displayName: adapter.displayName,
          version,
          status,
          durationMs: Date.now() - start,
          artifacts: normalized.artifacts,
          errorMessage: normalized.meta?.errorMessage,
          installHint: normalized.meta?.installHint ?? adapter.installHint,
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

  // critical: merge across engines AFTER canonicalization
  return {
    findings: mergeCanonicalFindings(findings),
    meta: meta.sort((a, b) => selectedEngines.indexOf(a.engineId) - selectedEngines.indexOf(b.engineId)),
  };
}
