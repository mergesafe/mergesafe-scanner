// packages/core/src/index.ts
import crypto from 'node:crypto';
import path from 'node:path';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export interface FindingLocation {
  filePath: string;
  line: number;
  column?: number;
}

export interface FindingEvidence {
  excerpt?: string;
  excerptHash?: string;
  note: string;
  ruleId?: string;
  matchType?: 'regex' | 'taint' | 'manifest' | 'heuristic';
  matchedSnippet?: string;
  matchSummary?: string;
  locations?: Array<{
    filePath: string;
    line: number;
    column?: number;
    endLine?: number;
    endColumn?: number;
  }>;
}

export interface EngineSource {
  engineId: string;
  engineRuleId?: string;
  engineSeverity?: string;
  message?: string;
}

export interface Finding {
  findingId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  owaspMcpTop10: string;
  engineSources: EngineSource[];
  locations: FindingLocation[];
  evidence: FindingEvidence;
  remediation: string;
  references: string[];
  tags: string[];
  fingerprint: string;
}

/**
 * ScanStatus answers: "Did the scan run and how complete was it?"
 * Gate answers: "Does this scan fail CI/policy based on failOn?"
 */
export type ScanStatus = 'OK' | 'PARTIAL' | 'FAILED';
export type GateStatus = 'PASS' | 'FAIL';

export interface ScanGate {
  status: GateStatus;
  failOn: 'critical' | 'high' | 'none';
  reason: string;
}

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';

  /**
   * New: scan completion status (not a policy verdict).
   */
  scanStatus: ScanStatus;

  /**
   * Policy/CI gate outcome.
   */
  gate: ScanGate;

  /**
   * Additive explicit gate status (same value as gate.status).
   */
  gateStatus?: GateStatus;

  /**
   * Back-compat: previously used as a PASS/FAIL "status".
   * Deprecated because it was ambiguous vs grade and scan completion.
   * Keep it equal to gate.status.
   */
  status: GateStatus;
}

export interface EngineExecutionMeta {
  engineId: string;
  displayName: string;
  version: string;
  status: 'ok' | 'skipped' | 'failed' | 'timeout';
  durationMs: number;
  errorMessage?: string;
  installHint?: string;
  artifacts?: {
    json?: string;
    sarif?: string;
  };
}

export type EngineExecutionStatus = EngineExecutionMeta['status'] | 'preflight-failed';

export interface ScanStatusCounts {
  selected: number;
  succeeded: number;
  nonSuccess: number;
}

export interface ScanMeta {
  scannedPath: string;
  generatedAt: string;
  mode: 'standard' | 'fast' | 'deep';
  timeout: number;
  concurrency: number;
  redacted: boolean;
  engines?: EngineExecutionMeta[];
}

export interface ScanResult {
  meta: ScanMeta;
  summary: ScanSummary;
  findings: Finding[];
  byEngine?: Record<string, number>;
}

/**
 * Canonical engine IDs supported by MergeSafe.
 */
export const AVAILABLE_ENGINES = ['mergesafe', 'semgrep', 'gitleaks', 'cisco', 'osv', 'trivy'] as const;
export type EngineId = (typeof AVAILABLE_ENGINES)[number];

/**
 * Shared default engine list across CLI / Core / Action/docs.
 * Note: Engines may be SKIPPED when they cannot run (missing binary, no targets, etc).
 */
export const DEFAULT_ENGINES: readonly EngineId[] = ['mergesafe', 'semgrep', 'gitleaks', 'cisco', 'osv'];

/**
 * Type guard for narrowing user-provided strings to EngineId.
 */
export function isEngineId(v: string): v is EngineId {
  return (AVAILABLE_ENGINES as readonly string[]).includes(v);
}

export type CiscoMode = 'auto' | 'static' | 'known-configs' | 'config' | 'remote' | 'stdio';

export interface CiscoConfig {
  enabled?: boolean;
  mode?: CiscoMode;

  // static
  toolsPath?: string;

  // config/remote/stdio
  configPath?: string;
  serverUrl?: string;
  stdioCommand?: string;
  stdioArgs?: string[];

  // auth (optional; depends on how you call Cisco)
  bearerToken?: string;
  headers?: string[];

  // analyzers (default should remain 'yara' for offline behavior)
  analyzers?: string;
}

/**
 * PR4: Path normalization policy for outputs
 */
export type PathMode = 'relative' | 'absolute';
export type VerifyDownloadsMode = 'off' | 'warn' | 'strict';

export interface CliConfig {
  outDir: string;
  format: string[];
  mode: 'standard' | 'fast' | 'deep';
  timeout: number;
  concurrency: number;
  failOn: 'critical' | 'high' | 'none';
  failOnScanStatus?: 'none' | 'partial' | 'failed' | 'any';
  redact: boolean;
  autoInstall: boolean;
  verifyDownloads?: VerifyDownloadsMode;
  maxFileBytes?: number;
  engines?: string[];

  /**
   * PR4: controls how file paths are written in outputs.
   * - relative: repo-relative to scanRoot (default in CLI)
   * - absolute: absolute machine paths
   */
  pathMode?: PathMode;

  /**
   * PR4: absolute scan root used to compute relative paths.
   * Populated by CLI (scan target root).
   */
  scanRoot?: string;

  /**
   * Optional engine-specific config bag.
   * Engines may ignore this if not relevant.
   */
  cisco?: CiscoConfig;
}

export interface RawFinding {
  ruleId: string;
  title: string;
  severity: Exclude<Severity, 'info'>;
  confidence: Confidence;
  category: string;
  owaspMcpTop10: string;
  filePath: string;
  line: number;
  evidence: string;
  evidencePayload?: {
    ruleId: string;
    matchType: 'regex' | 'taint' | 'manifest' | 'heuristic';
    matchedSnippet?: string;
    matchSummary?: string;
    locations?: Array<{
      filePath: string;
      line: number;
      column?: number;
      endLine?: number;
      endColumn?: number;
    }>;
  };
  remediation: string;
  references: string[];
  tags: string[];
}

/**
 * Deterministic comparator.
 * Avoids locale/ICU differences across OS runners (Windows/Linux/macOS).
 */
function asciiCompare(a: string, b: string): number {
  if (a === b) return 0;
  // JS < / > is deterministic by code unit ordering across platforms.
  return a < b ? -1 : 1;
}

function stableCompare(a: unknown, b: unknown): number {
  return asciiCompare(String(a ?? ''), String(b ?? ''));
}

export function stableHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

export function lineBucket(line: number): number {
  return Math.floor(Math.max(line, 1) / 5) * 5;
}

/**
 * Step 4: Fingerprint should be engine-agnostic.
 *
 * NOTE: Callers pass a "signal" string. In practice engines may pass evidence;
 * we normalize it to reduce drift (strip literals/whitespace/comments).
 */
function normalizeSignalText(input: string): string {
  const s = String(input ?? '');
  return s
    .replace(/\/\*[\s\S]*?\*\//g, ' ') // block comments
    .replace(/\/\/.*$/gm, ' ') // line comments
    .replace(/`[^`]*`/g, '`<str>`')
    .replace(/"[^"]*"/g, '"<str>"')
    .replace(/'[^']*'/g, "'<str>'")
    .replace(/\b\d+\b/g, '<num>')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase()
    .slice(0, 500);
}

/**
 * PR4: Normalize path for display/output keys (POSIX separators)
 */
export function toPosixPath(p: string): string {
  return String(p ?? '').replace(/\\/g, '/');
}

/**
 * Internal: normalize for stable key usage (no relativization).
 */
function normalizePathForKey(p: string): string {
  return toPosixPath(String(p || ''));
}

/* -------------------------------------------------------------------------- */
/* Cross-platform deterministic path + fingerprint debug (Windows/Linux parity) */
/* -------------------------------------------------------------------------- */

/**
 * Enable debug logs (safe in CI):
 * - MERGESAFE_DEBUG_FINGERPRINT=1 (or MERGESAFE_DEBUG=1)
 * - MERGESAFE_DEBUG_LIMIT=200
 */
const __MS_DEBUG_FP =
  process.env.MERGESAFE_DEBUG_FINGERPRINT === '1' || process.env.MERGESAFE_DEBUG === '1';
const __MS_DEBUG_LIMIT = Number(process.env.MERGESAFE_DEBUG_LIMIT ?? 200);
let __msDebugCount = 0;

function msDebug(event: string, data: Record<string, unknown>) {
  if (!__MS_DEBUG_FP) return;
  if (__msDebugCount++ >= __MS_DEBUG_LIMIT) return;
  try {
    console.log(`[mergesafe-debug:${event}] ${JSON.stringify(data)}`);
  } catch {
    console.log(`[mergesafe-debug:${event}]`, data);
  }
}

// Treat Windows drive paths as absolute even when code runs on Linux
function isWindowsAbs(p: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(p);
}
function isAbsAnyOS(p: string): boolean {
  const s = String(p ?? '');
  return s.startsWith('/') || s.startsWith('\\') || isWindowsAbs(s);
}

/**
 * Normalize absolute-ish paths in a deterministic way across OS.
 * - Windows drive paths: win32.normalize then POSIX separators
 * - POSIX paths: posix.normalize on POSIX-ified input
 */
function normalizeAbsAnyOS(p: string): string {
  const s = String(p ?? '');
  if (!s) return '';
  if (isWindowsAbs(s)) {
    return toPosixPath(path.win32.normalize(s));
  }
  return toPosixPath(path.posix.normalize(toPosixPath(s)));
}

/**
 * PR4: Convert a path into repo-relative or absolute form, then POSIX normalize.
 *
 * IMPORTANT: This implementation is OS-agnostic:
 * - It treats Windows drive paths as absolute even on Linux runners.
 * - It builds/join/relative using path.posix on POSIX-normalized strings.
 * - It normalizes scanRoot and file paths before computing relative.
 */
export function normalizePathForOutput(
  filePath: string,
  opts?: { scanRoot?: string; pathMode?: PathMode }
): string {
  const raw = String(filePath ?? '');
  const rawPosix = toPosixPath(raw);

  const scanRootRaw = opts?.scanRoot ? String(opts.scanRoot) : '';
  const scanRoot = scanRootRaw ? normalizeAbsAnyOS(scanRootRaw) : '';
  const pathMode: PathMode = opts?.pathMode ?? 'relative';

  if (!scanRoot) {
    msDebug('path.noScanRoot', {
      rawPosix,
      pathMode,
      rawIsAbsAnyOS: isAbsAnyOS(raw),
    });
    return rawPosix;
  }

  const absRoot = scanRoot;

  const absFile = isAbsAnyOS(raw)
    ? normalizeAbsAnyOS(raw)
    : normalizeAbsAnyOS(path.posix.join(absRoot, rawPosix));

  if (pathMode === 'absolute') {
    msDebug('path.absolute', {
      rawPosix,
      rawIsAbsAnyOS: isAbsAnyOS(raw),
      scanRootHash: stableHash(absRoot),
      absFileHash: stableHash(absFile),
    });
    return absFile;
  }

  let rel = path.posix.relative(absRoot, absFile);

  // Ensure a stable no-leading-dot convention.
  rel = rel.replace(/^[.][\\/]/, '').replace(/^\.\//, '');

  if (!rel) {
    // Edge case: absFile === absRoot
    rel = path.posix.basename(absFile) || 'unknown';
  }

  const out = toPosixPath(rel);

  msDebug('path.relative', {
    rawPosix,
    rawIsAbsAnyOS: isAbsAnyOS(raw),
    scanRootHash: stableHash(absRoot),
    absFileHash: stableHash(absFile),
    out,
  });

  return out;
}

/**
 * PR4: Apply path policy to all finding locations (without changing other fields).
 * This is intended to be called once in CLI before writing outputs.
 */
export function normalizeFindingPaths(
  findings: Finding[],
  opts?: { scanRoot?: string; pathMode?: PathMode }
): Finding[] {
  const scanRoot = opts?.scanRoot;
  const pathMode = opts?.pathMode;

  return (findings ?? []).map((f) => {
    const locs = (f.locations ?? []).map((l) => ({
      ...l,
      filePath: normalizePathForOutput(l.filePath, { scanRoot, pathMode }),
    }));

    // Important: fingerprint is already stable and engine-agnostic; do NOT recompute here.
    return { ...f, locations: locs };
  });
}

/**
 * Canonicalize the path portion of the fingerprint in a cross-platform way.
 * If scanRoot is available, always fingerprint on *relative POSIX* paths,
 * regardless of output mode, so Windows/Linux agree.
 */
function normalizePathForFingerprint(filePath: string, opts?: { scanRoot?: string }): string {
  const scanRoot = opts?.scanRoot ? String(opts.scanRoot) : undefined;
  if (!scanRoot) return normalizePathForKey(filePath);

  // Always fingerprint on relative paths (stable across OS/machines).
  return normalizePathForOutput(filePath, { scanRoot, pathMode: 'relative' });
}

/**
 * UPDATED: now accepts optional scanRoot anchor to eliminate OS-specific drift.
 * Also emits opt-in debug logs (hashed) to diagnose CI-only mismatches.
 */
export function findingFingerprint(
  filePath: string,
  line: number,
  signal: string,
  opts?: { scanRoot?: string }
): string {
  const fpPath = normalizePathForFingerprint(filePath, opts);
  const bucket = lineBucket(line);

  const sigNorm = normalizeSignalText(signal);
  const sigHash = stableHash(sigNorm);

  const fp = stableHash(`${fpPath}:${bucket}:${sigHash}`);

  msDebug('fingerprint', {
    rawPathPosix: toPosixPath(String(filePath ?? '')),
    rawIsAbsAnyOS: isAbsAnyOS(String(filePath ?? '')),
    fpPath,
    scanRootSet: Boolean(opts?.scanRoot),
    scanRootHash: opts?.scanRoot ? stableHash(normalizeAbsAnyOS(String(opts.scanRoot))) : '',
    line: Number(line ?? 0),
    bucket,
    sigHash,
    fp,
  });

  return fp;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const CONFIDENCE_RANK: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function maxConfidence(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] ? a : b;
}

function dedupeEngineSources(sources: EngineSource[]): EngineSource[] {
  const seen = new Set<string>();
  const out: EngineSource[] = [];
  for (const s of sources) {
    const key = `${s.engineId}:${s.engineRuleId ?? ''}:${s.engineSeverity ?? ''}:${s.message ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out;
}

function dedupeLocations(locs: FindingLocation[]): FindingLocation[] {
  const seen = new Set<string>();
  const out: FindingLocation[] = [];
  for (const l of locs) {
    const key = `${normalizePathForKey(l.filePath)}:${l.line}:${l.column ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ...l, filePath: normalizePathForKey(l.filePath) });
  }
  return out;
}

function pickBestEvidence(evidences: FindingEvidence[]): FindingEvidence {
  const structured = evidences.find(
    (e) =>
      Boolean(e.ruleId) ||
      Boolean(e.matchType) ||
      Boolean(e.matchSummary) ||
      Boolean(e.matchedSnippet) ||
      Boolean(e.locations?.length)
  );

  // Prefer an excerpt (longest non-empty), otherwise keep first excerptHash.
  const withExcerpt = evidences
    .filter((e) => typeof e.excerpt === 'string' && e.excerpt.trim().length > 0)
    .sort((a, b) => b.excerpt!.trim().length - a.excerpt!.trim().length);

  if (withExcerpt.length) {
    const base = withExcerpt[0];
    return {
      excerpt: base.excerpt,
      note: 'Merged evidence (best available excerpt)',
      ...(structured?.ruleId ? { ruleId: structured.ruleId } : {}),
      ...(structured?.matchType ? { matchType: structured.matchType } : {}),
      ...(structured?.matchSummary ? { matchSummary: structured.matchSummary } : {}),
      ...(structured?.matchedSnippet ? { matchedSnippet: structured.matchedSnippet } : {}),
      ...(structured?.locations?.length ? { locations: structured.locations } : {}),
    };
  }

  const withHash = evidences.find((e) => typeof e.excerptHash === 'string' && e.excerptHash.trim().length > 0);
  if (withHash) {
    return {
      excerptHash: withHash.excerptHash,
      note: 'Merged evidence (hash only)',
      ...(structured?.ruleId ? { ruleId: structured.ruleId } : {}),
      ...(structured?.matchType ? { matchType: structured.matchType } : {}),
      ...(structured?.matchSummary ? { matchSummary: structured.matchSummary } : {}),
      ...(structured?.matchedSnippet ? { matchedSnippet: structured.matchedSnippet } : {}),
      ...(structured?.locations?.length ? { locations: structured.locations } : {}),
    };
  }

  return {
    note: 'Merged evidence unavailable',
    ...(structured?.ruleId ? { ruleId: structured.ruleId } : {}),
    ...(structured?.matchType ? { matchType: structured.matchType } : {}),
    ...(structured?.matchSummary ? { matchSummary: structured.matchSummary } : {}),
    ...(structured?.matchedSnippet ? { matchedSnippet: structured.matchedSnippet } : {}),
    ...(structured?.locations?.length ? { locations: structured.locations } : {}),
  };
}

/**
 * Step 4: True cross-engine merge key.
 */
const ENGINE_PRIORITY: Record<string, number> = {
  mergesafe: 1,
  semgrep: 2,
  gitleaks: 3,
  cisco: 4,
  osv: 5,
  trivy: 6,
};

/**
 * PR4: stable sort helper for findings.
 * Sort key chain:
 *   severity(desc) -> confidence(desc) -> rule-ish/category -> filePath -> line -> column -> fingerprint -> title -> findingId
 *
 * NOTE: this returns a new array and does not mutate the input.
 */
export function stableSortFindings(findings: Finding[]): Finding[] {
  const arr = [...(findings ?? [])];

  arr.sort((a, b) => {
    // severity DESC
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;

    // confidence DESC
    const conf = CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence];
    if (conf !== 0) return conf;

    // prefer mergesafe-first if everything else equal (helps determinism when merged)
    const aEng = (a.engineSources?.[0]?.engineId ?? '').toLowerCase();
    const bEng = (b.engineSources?.[0]?.engineId ?? '').toLowerCase();
    const ap = ENGINE_PRIORITY[aEng] ?? 99;
    const bp = ENGINE_PRIORITY[bEng] ?? 99;
    if (ap !== bp) return ap - bp;

    // category / title / owasp provide extra stability
    const cat = stableCompare(a.category, b.category);
    if (cat !== 0) return cat;

    const owasp = stableCompare(a.owaspMcpTop10, b.owaspMcpTop10);
    if (owasp !== 0) return owasp;

    // location path/line/col
    const aLoc = a.locations?.[0];
    const bLoc = b.locations?.[0];

    const fp = stableCompare(aLoc?.filePath ?? '', bLoc?.filePath ?? '');
    if (fp !== 0) return fp;

    const ln = Number(aLoc?.line ?? 0) - Number(bLoc?.line ?? 0);
    if (ln !== 0) return ln;

    const col = Number(aLoc?.column ?? 0) - Number(bLoc?.column ?? 0);
    if (col !== 0) return col;

    // fingerprint, then title, then findingId
    const fpa = stableCompare(a.fingerprint ?? '', b.fingerprint ?? '');
    if (fpa !== 0) return fpa;

    const t = stableCompare(a.title ?? '', b.title ?? '');
    if (t !== 0) return t;

    return stableCompare(a.findingId ?? '', b.findingId ?? '');
  });

  return arr;
}

// ✅ IMPORTANT: Make this Set<string> so .has(string) is valid (fixes TS2345).
const ENGINE_ID_TAGS: ReadonlySet<string> = new Set<string>(AVAILABLE_ENGINES);
const GENERIC_TAGS = new Set(['mcp', 'node', 'javascript', 'typescript', 'python', 'security', 'scanner']);

function normalizeTag(t: string): string {
  return String(t || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\-_]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function normalizeKeywordText(s: string): string {
  return String(s || '')
    .toLowerCase()
    .replace(/[_./-]+/g, ' ')
    .replace(/[^a-z0-9\s]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function deriveFamilyKey(finding: Finding): string {
  const parts: string[] = [];

  parts.push(finding.title);
  parts.push(finding.category);
  parts.push(finding.owaspMcpTop10);

  for (const src of finding.engineSources ?? []) {
    parts.push(src.engineRuleId ?? '');
    parts.push(src.message ?? '');
  }

  for (const t of finding.tags ?? []) parts.push(t);

  const haystack = normalizeKeywordText(parts.filter(Boolean).join(' '));

  if (
    /\b(command|cmd)\b/.test(haystack) &&
    /\b(exec|execute|execution|shell|spawn|child process|childprocess)\b/.test(haystack)
  ) {
    return 'command-exec';
  }
  if (/\b(exec|execfile|execsync|spawn|spawnsync|child_process)\b/.test(haystack)) {
    return 'command-exec';
  }

  if (/\b(arbitrary|any)\b/.test(haystack) && /\b(file)\b/.test(haystack) && /\b(read)\b/.test(haystack)) {
    return 'fs-read';
  }
  if (/\b(file|filesystem|fs)\b/.test(haystack) && /\b(read|readfile|read-file|read_file)\b/.test(haystack)) {
    return 'fs-read';
  }

  if (
    /\b(file|filesystem|fs)\b/.test(haystack) &&
    /\b(write|writefile|write-file|write_file|append|overwrite)\b/.test(haystack)
  ) {
    return 'fs-write';
  }

  if (/\b(network|egress|ssrf)\b/.test(haystack)) {
    return 'net-egress';
  }
  if (
    /\b(http|https|fetch|axios|request|curl|url)\b/.test(haystack) &&
    /\b(allowlist|whitelist|restricted|validate)\b/.test(haystack)
  ) {
    return 'net-egress';
  }
  if (/\b(http|https|fetch|axios|request|curl|url)\b/.test(haystack)) {
    return 'net-egress';
  }

  if (
    /\b(secret|token|apikey|api key|credential|bearer)\b/.test(haystack) &&
    /\b(log|print|dump|console)\b/.test(haystack)
  ) {
    return 'secrets-log';
  }

  if (/\b(missing|no|without)\b/.test(haystack) && /\b(auth|authentication|authorize|middleware)\b/.test(haystack)) {
    return 'auth-missing';
  }

  if (/\b(scope|scopes|full_access|allow_all|\*)\b/.test(haystack)) {
    return 'scope-wildcard';
  }

  if (/\b(dynamic)\b/.test(haystack) && /\b(tool|register|registration|registry)\b/.test(haystack)) {
    return 'dynamic-tool-registration';
  }

  if (
    /\btools(-|\s)?list\.json\b/.test(haystack) ||
    /\btools manifest\b/.test(haystack) ||
    /\bmanifest\b/.test(haystack)
  ) {
    if (/\bexec\b|\bcommand\b|\bshell\b/.test(haystack)) return 'manifest-command-exec';
    if (/\bread\b|\bfile read\b/.test(haystack)) return 'manifest-fs-read';
    if (/\bwrite\b|\bfile write\b/.test(haystack)) return 'manifest-fs-write';
    if (/\bhttp\b|\bfetch\b|\burl\b|\begress\b/.test(haystack)) return 'manifest-net-egress';
    if (/\btoken\b|\bsecret\b|\blog\b/.test(haystack)) return 'manifest-secrets-log';
    return 'manifest-risk';
  }

  const noisy = new Set([
    'potential',
    'avoid',
    'consider',
    'using',
    'user',
    'controlled',
    'input',
    'from',
    'without',
    'with',
  ]);
  const tokens = haystack
    .split(' ')
    .filter(Boolean)
    .filter((t) => !noisy.has(t));
  return tokens.slice(0, 6).join('-') || 'unknown';
}

function mergeKeyForFinding(finding: Finding): string {
  const loc = finding.locations?.[0] ?? { filePath: 'unknown', line: 1 };
  const filePath = normalizePathForKey(loc.filePath);
  const line = Number((loc as any).line ?? 1);

  const family = deriveFamilyKey(finding);
  const category = normalizeTag(finding.category);
  const owasp = normalizeTag(finding.owaspMcpTop10);

  return `${filePath}:${lineBucket(line)}:${category}:${owasp}:${family}`;
}

function stableStringArray(arr: string[] | undefined): string[] {
  const out = [...new Set((arr ?? []).map((x) => String(x ?? '').trim()).filter(Boolean))];
  out.sort(asciiCompare); // ✅ deterministic across OS
  return out;
}

export function toFinding(raw: RawFinding, redact: boolean, opts?: { scanRoot?: string }): Finding {
  const snippetHash = stableHash(raw.evidence);

  const tags = stableStringArray(raw.tags);
  const refs = stableStringArray(raw.references);

  const signal = [raw.ruleId, raw.category, raw.owaspMcpTop10, ...tags, raw.title].filter(Boolean).join('|');

  const fingerprint = findingFingerprint(raw.filePath, raw.line, signal, opts);

  // Store a canonical path early (helps merge keys & cross-platform determinism)
  const canonicalPath = normalizePathForFingerprint(raw.filePath, opts);

  const payload = raw.evidencePayload;
  const normalizedPayloadLocations = (payload?.locations ?? [])
    .map((loc) => ({
      filePath: normalizePathForFingerprint(loc.filePath, opts),
      line: Math.max(1, Number(loc.line ?? 1)),
      column: loc.column,
      endLine: loc.endLine,
      endColumn: loc.endColumn,
    }))
    .sort((a, b) => {
      const p = stableCompare(a.filePath, b.filePath);
      if (p !== 0) return p;
      const l = Number(a.line ?? 0) - Number(b.line ?? 0);
      if (l !== 0) return l;
      const c = Number(a.column ?? 0) - Number(b.column ?? 0);
      if (c !== 0) return c;
      const el = Number(a.endLine ?? 0) - Number(b.endLine ?? 0);
      if (el !== 0) return el;
      return Number(a.endColumn ?? 0) - Number(b.endColumn ?? 0);
    });

  return {
    findingId: `${raw.ruleId}-${fingerprint}`,
    title: raw.title,
    severity: raw.severity,
    confidence: raw.confidence,
    category: raw.category,
    owaspMcpTop10: raw.owaspMcpTop10,
    engineSources: [
      { engineId: 'mergesafe', engineRuleId: raw.ruleId, engineSeverity: raw.severity, message: raw.title },
    ],
    locations: [{ filePath: canonicalPath, line: raw.line }],
    evidence: redact
      ? { excerptHash: snippetHash, note: 'Redacted evidence' }
      : {
          excerpt: raw.evidence,
          note: 'Static pattern match',
          ...(payload
            ? {
                ruleId: payload.ruleId,
                matchType: payload.matchType,
                ...(payload.matchSummary ? { matchSummary: payload.matchSummary } : {}),
                ...(payload.matchedSnippet ? { matchedSnippet: payload.matchedSnippet.slice(0, 160) } : {}),
                ...(normalizedPayloadLocations.length ? { locations: normalizedPayloadLocations } : {}),
              }
            : {}),
        },
    remediation: raw.remediation,
    references: refs,
    tags,
    fingerprint,
  };
}

export function dedupeFindings(rawFindings: RawFinding[], redact: boolean, opts?: { scanRoot?: string }): Finding[] {
  const map = new Map<string, Finding>();
  for (const raw of rawFindings) {
    const finding = toFinding(raw, redact, opts);
    const existing = map.get(finding.fingerprint);
    if (!existing) {
      map.set(finding.fingerprint, finding);
      continue;
    }
    existing.locations.push(...finding.locations);
    existing.engineSources.push(...finding.engineSources);
  }
  return [...map.values()];
}

/**
 * Step 4: Truly cross-engine merge.
 */
export function mergeCanonicalFindings(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const f of findings) {
    const key = mergeKeyForFinding(f);
    const arr = groups.get(key);
    if (arr) arr.push(f);
    else groups.set(key, [f]);
  }

  const merged: Finding[] = [];

  for (const [, group] of groups) {
    const primary = [...group].sort((a, b) => {
      const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (sev !== 0) return sev;

      const conf = CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence];
      if (conf !== 0) return conf;

      const aEng = (a.engineSources?.[0]?.engineId ?? '').toLowerCase();
      const bEng = (b.engineSources?.[0]?.engineId ?? '').toLowerCase();
      const ap = ENGINE_PRIORITY[aEng] ?? 99;
      const bp = ENGINE_PRIORITY[bEng] ?? 99;
      if (ap !== bp) return ap - bp;

      return stableCompare(a.findingId, b.findingId);
    })[0];

    const allSources: EngineSource[] = [];
    const allTags: string[] = [];
    const allRefs: string[] = [];
    const allLocs: FindingLocation[] = [];
    const allEvidence: FindingEvidence[] = [];

    let severity: Severity = primary.severity;
    let confidence: Confidence = primary.confidence;

    for (const f of group) {
      severity = maxSeverity(severity, f.severity);
      confidence = maxConfidence(confidence, f.confidence);

      allSources.push(...(f.engineSources ?? []));
      allTags.push(...(f.tags ?? []));
      allRefs.push(...(f.references ?? []));
      allLocs.push(...(f.locations ?? []));
      if (f.evidence) allEvidence.push(f.evidence);
    }

    const mergedFinding: Finding = {
      ...primary,

      severity,
      confidence,

      engineSources: dedupeEngineSources(allSources).sort((a, b) => {
        const e = stableCompare(a.engineId, b.engineId);
        if (e !== 0) return e;
        const r = stableCompare(a.engineRuleId ?? '', b.engineRuleId ?? '');
        if (r !== 0) return r;
        return stableCompare(a.message ?? '', b.message ?? '');
      }),

      tags: [...new Set(allTags.map((t) => String(t || '').trim()).filter(Boolean))]
        .filter((t) => !ENGINE_ID_TAGS.has(normalizeTag(t)))
        .filter((t) => !GENERIC_TAGS.has(normalizeTag(t)))
        .sort(asciiCompare),

      references: [...new Set(allRefs.map((r) => String(r || '').trim()).filter(Boolean))].sort(asciiCompare),

      locations: dedupeLocations(allLocs).sort((a, b) => {
        const p = stableCompare(a.filePath, b.filePath);
        if (p !== 0) return p;
        const l = (a.line ?? 0) - (b.line ?? 0);
        if (l !== 0) return l;
        return (a.column ?? 0) - (b.column ?? 0);
      }),

      evidence: pickBestEvidence(allEvidence),
    };

    merged.push(mergedFinding);
  }

  return merged.sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;

    const aLoc = a.locations?.[0];
    const bLoc = b.locations?.[0];
    const fp = stableCompare(aLoc?.filePath ?? '', bLoc?.filePath ?? '');
    if (fp !== 0) return fp;

    const ln = Number(aLoc?.line ?? 0) - Number(bLoc?.line ?? 0);
    if (ln !== 0) return ln;

    return stableCompare(a.title ?? '', b.title ?? '');
  });
}

export function shouldFail(bySeverity: Record<Severity, number>, failOn: CliConfig['failOn']): boolean {
  if (failOn === 'none') return false;
  if (failOn === 'critical') return bySeverity.critical > 0;
  return bySeverity.critical > 0 || bySeverity.high > 0;
}

function gateReason(bySeverity: Record<Severity, number>, failOn: CliConfig['failOn']): string {
  if (failOn === 'none') return 'failOn=none (policy gate disabled)';
  if (failOn === 'critical') {
    return bySeverity.critical > 0 ? `critical=${bySeverity.critical} (>0)` : 'no critical findings';
  }
  // failOn=high
  if (bySeverity.critical > 0 || bySeverity.high > 0) {
    return `critical=${bySeverity.critical}, high=${bySeverity.high} (threshold: high+)`;
  }
  return 'no critical/high findings';
}

/**
 * Deterministic scan completeness rules from selected engine execution statuses.
 * - OK: all selected engines succeeded
 * - PARTIAL: at least one selected engine succeeded and at least one did not
 * - FAILED: no selected engines succeeded, or a hard scan error occurred
 */
export function computeScanStatus(
  statuses: EngineExecutionStatus[],
  opts?: { hardError?: boolean }
): { scanStatus: ScanStatus; counts: ScanStatusCounts } {
  const selected = statuses.length;
  const succeeded = statuses.filter((s) => s === 'ok').length;
  const nonSuccess = selected - succeeded;

  if (opts?.hardError) {
    return { scanStatus: 'FAILED', counts: { selected, succeeded, nonSuccess } };
  }

  if (selected === 0) {
    return { scanStatus: 'OK', counts: { selected, succeeded, nonSuccess } };
  }

  if (succeeded === selected) {
    return { scanStatus: 'OK', counts: { selected, succeeded, nonSuccess } };
  }

  if (succeeded > 0) {
    return { scanStatus: 'PARTIAL', counts: { selected, succeeded, nonSuccess } };
  }

  return { scanStatus: 'FAILED', counts: { selected, succeeded, nonSuccess } };
}

export function deriveScanStatus(engines?: EngineExecutionMeta[], opts?: { hardError?: boolean }): ScanStatus {
  const statuses = (engines ?? []).map((engine) => engine.status as EngineExecutionStatus);
  return computeScanStatus(statuses, opts).scanStatus;
}

export function summarize(
  findings: Finding[],
  failOn: CliConfig['failOn'],
  opts?: { engines?: EngineExecutionMeta[]; scanStatus?: ScanStatus }
): ScanSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;

  let score = 100 - bySeverity.critical * 30 - bySeverity.high * 15 - bySeverity.medium * 7 - bySeverity.low * 2;
  score = Math.max(0, score);

  const grade: ScanSummary['grade'] =
    score >= 90 ? 'A' :
    score >= 80 ? 'B' :
    score >= 70 ? 'C' :
    score >= 60 ? 'D' : 'F';

  const gateStatus: GateStatus = shouldFail(bySeverity, failOn) ? 'FAIL' : 'PASS';

  const scanStatus: ScanStatus =
    opts?.scanStatus ??
    deriveScanStatus(opts?.engines) ??
    'OK';

  const gate: ScanGate = {
    status: gateStatus,
    failOn,
    reason: gateReason(bySeverity, failOn),
  };

  return {
    totalFindings: findings.length,
    bySeverity,
    score,
    grade,

    scanStatus,
    gate,
    gateStatus: gateStatus,

    // back-compat alias (deprecated)
    status: gateStatus,
  };
}
