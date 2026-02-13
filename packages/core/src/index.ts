// packages/core/src/index.ts
import crypto from 'node:crypto';

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
export type ScanStatus = 'COMPLETED' | 'PARTIAL' | 'FAILED';
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
   * New: policy/CI gate outcome.
   */
  gate: ScanGate;

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

export interface ScanMeta {
  scannedPath: string;
  generatedAt: string;
  mode: 'fast' | 'deep';
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

export interface CliConfig {
  outDir: string;
  format: readonly string[];
  pathMode?: 'relative' | 'absolute';
  mode: 'fast' | 'deep';
  timeout: number;
  concurrency: number;
  failOn: 'critical' | 'high' | 'none';
  redact: boolean;
  autoInstall: boolean;
  engines?: string[];

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
  remediation: string;
  references: string[];
  tags: string[];
}

/**
 * Deterministic string comparator (do NOT use localeCompare; can vary by runtime/locale).
 */
function cmpStr(a: string, b: string): number {
  const A = String(a ?? '');
  const B = String(b ?? '');
  return A < B ? -1 : A > B ? 1 : 0;
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

function normalizePathForKey(p: string): string {
  return String(p || '').replace(/\\/g, '/');
}

export function findingFingerprint(filePath: string, line: number, signal: string): string {
  const fpPath = normalizePathForKey(filePath);
  const sig = normalizeSignalText(signal);
  return stableHash(`${fpPath}:${lineBucket(line)}:${stableHash(sig)}`);
}

export function canonicalFingerprintInput(args: {
  filePath: string;
  line: number;
  ruleId?: string;
  category?: string;
  owaspMcpTop10?: string;
  title?: string;
  tags?: readonly string[];
}): string {
  const normalizedTags = [...new Set((args.tags ?? []).map((t) => normalizeTag(t)).filter(Boolean))].sort(cmpStr);

  return [
    normalizePathForKey(args.filePath),
    String(lineBucket(args.line)),
    normalizeTag(args.ruleId ?? ''),
    normalizeTag(args.category ?? ''),
    normalizeTag(args.owaspMcpTop10 ?? ''),
    normalizeKeywordText(args.title ?? ''),
    normalizedTags.join(','),
  ].join('|');
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
  // Prefer an excerpt (longest non-empty), otherwise keep first excerptHash.
  const withExcerpt = evidences
    .filter((e) => typeof e.excerpt === 'string' && e.excerpt.trim().length > 0)
    .sort((a, b) => (b.excerpt!.trim().length || 0) - (a.excerpt!.trim().length || 0));

  if (withExcerpt.length) {
    return {
      excerpt: withExcerpt[0].excerpt,
      note: 'Merged evidence (best available excerpt)',
    };
  }

  const withHash = evidences.find((e) => typeof e.excerptHash === 'string' && e.excerptHash.trim().length > 0);
  return withHash
    ? { excerptHash: withHash.excerptHash, note: 'Merged evidence (hash only)' }
    : { note: 'Merged evidence unavailable' };
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

// ✅ IMPORTANT: Make this Set<string> so .has(string) is valid (fixes TS2345).
const ENGINE_ID_TAGS: ReadonlySet<string> = new Set<string>(AVAILABLE_ENGINES);
const GENERIC_TAGS: ReadonlySet<string> = new Set(['mcp', 'node', 'javascript', 'typescript', 'python', 'security', 'scanner']);

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

  // IMPORTANT: stabilize ordering to avoid drift across runs/platforms
  const stableSources = [...(finding.engineSources ?? [])].sort((a, b) => {
    return (
      cmpStr(String(a.engineId), String(b.engineId)) ||
      cmpStr(String(a.engineRuleId ?? ''), String(b.engineRuleId ?? '')) ||
      cmpStr(String(a.engineSeverity ?? ''), String(b.engineSeverity ?? '')) ||
      cmpStr(String(a.message ?? ''), String(b.message ?? ''))
    );
  });

  for (const src of stableSources) {
    parts.push(src.engineRuleId ?? '');
    parts.push(src.message ?? '');
  }

  const stableTags = [...(finding.tags ?? [])].map((t) => String(t ?? '')).sort(cmpStr);
  for (const t of stableTags) parts.push(t);

  const haystack = normalizeKeywordText(parts.filter(Boolean).join(' '));

  if (/\b(command|cmd)\b/.test(haystack) && /\b(exec|execute|execution|shell|spawn|child process|childprocess)\b/.test(haystack)) {
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

  if (/\b(file|filesystem|fs)\b/.test(haystack) && /\b(write|writefile|write-file|write_file|append|overwrite)\b/.test(haystack)) {
    return 'fs-write';
  }

  if (/\b(network|egress|ssrf)\b/.test(haystack)) {
    return 'net-egress';
  }
  if (/\b(http|https|fetch|axios|request|curl|url)\b/.test(haystack) && /\b(allowlist|whitelist|restricted|validate)\b/.test(haystack)) {
    return 'net-egress';
  }
  if (/\b(http|https|fetch|axios|request|curl|url)\b/.test(haystack)) {
    return 'net-egress';
  }

  if (/\b(secret|token|apikey|api key|credential|bearer)\b/.test(haystack) && /\b(log|print|dump|console)\b/.test(haystack)) {
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

  if (/\btools(-|\s)?list\.json\b/.test(haystack) || /\btools manifest\b/.test(haystack) || /\bmanifest\b/.test(haystack)) {
    if (/\bexec\b|\bcommand\b|\bshell\b/.test(haystack)) return 'manifest-command-exec';
    if (/\bread\b|\bfile read\b/.test(haystack)) return 'manifest-fs-read';
    if (/\bwrite\b|\bfile write\b/.test(haystack)) return 'manifest-fs-write';
    if (/\bhttp\b|\bfetch\b|\burl\b|\begress\b/.test(haystack)) return 'manifest-net-egress';
    if (/\btoken\b|\bsecret\b|\blog\b/.test(haystack)) return 'manifest-secrets-log';
    return 'manifest-risk';
  }

  const noisy = new Set(['potential', 'avoid', 'consider', 'using', 'user', 'controlled', 'input', 'from', 'without', 'with']);
  const tokens = haystack.split(' ').filter(Boolean).filter((t) => !noisy.has(t));
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

export function toFinding(raw: RawFinding, redact: boolean): Finding {
  const snippetHash = stableHash(raw.evidence);

  const canonicalInput = canonicalFingerprintInput({
    filePath: raw.filePath,
    line: raw.line,
    ruleId: raw.ruleId,
    category: raw.category,
    owaspMcpTop10: raw.owaspMcpTop10,
    title: raw.title,
    tags: raw.tags,
  });
  const fingerprint = stableHash(canonicalInput);

  return {
    findingId: `ms-${fingerprint}`,
    title: raw.title,
    severity: raw.severity,
    confidence: raw.confidence,
    category: raw.category,
    owaspMcpTop10: raw.owaspMcpTop10,
    engineSources: [{ engineId: 'mergesafe', engineRuleId: raw.ruleId, engineSeverity: raw.severity, message: raw.title }],
    locations: [{ filePath: normalizePathForKey(raw.filePath), line: raw.line }],
    evidence: redact ? { excerptHash: snippetHash, note: 'Redacted evidence' } : { excerpt: raw.evidence, note: 'Static pattern match' },
    remediation: raw.remediation,
    references: [...(raw.references ?? [])].sort(cmpStr),
    tags: [...(raw.tags ?? [])].sort(cmpStr),
    fingerprint,
  };
}

export function sortFindingsDeterministic(findings: Finding[]): Finding[] {
  const normalized = findings.map((f) => ({
    ...f,
    engineSources: [...(f.engineSources ?? [])].sort((a, b) => {
      return (
        cmpStr(String(a.engineId), String(b.engineId)) ||
        cmpStr(String(a.engineRuleId ?? ''), String(b.engineRuleId ?? '')) ||
        cmpStr(String(a.message ?? ''), String(b.message ?? ''))
      );
    }),
    tags: [...new Set((f.tags ?? []).map((t) => String(t).trim()).filter(Boolean))].sort(cmpStr),
    references: [...new Set((f.references ?? []).map((r) => String(r).trim()).filter(Boolean))].sort(cmpStr),
    locations: [...(f.locations ?? [])].sort((a, b) => {
      return cmpStr(String(a.filePath), String(b.filePath)) || Number(a.line ?? 0) - Number(b.line ?? 0) || Number(a.column ?? 0) - Number(b.column ?? 0);
    }),
  }));

  return normalized.sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;

    const aLoc = a.locations?.[0];
    const bLoc = b.locations?.[0];

    const fp = cmpStr(String(aLoc?.filePath ?? ''), String(bLoc?.filePath ?? ''));
    if (fp !== 0) return fp;

    const ln = Number(aLoc?.line ?? 0) - Number(bLoc?.line ?? 0);
    if (ln !== 0) return ln;

    return cmpStr(String(a.findingId ?? ''), String(b.findingId ?? ''));
  });
}

export function dedupeFindings(rawFindings: RawFinding[], redact: boolean): Finding[] {
  const map = new Map<string, Finding>();
  for (const raw of rawFindings) {
    const finding = toFinding(raw, redact);
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

      return cmpStr(String(a.findingId), String(b.findingId));
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
        return (
          cmpStr(String(a.engineId), String(b.engineId)) ||
          cmpStr(String(a.engineRuleId ?? ''), String(b.engineRuleId ?? '')) ||
          cmpStr(String(a.message ?? ''), String(b.message ?? ''))
        );
      }),

      tags: [...new Set(allTags.map((t) => String(t || '').trim()).filter(Boolean))]
        .filter((t) => !ENGINE_ID_TAGS.has(normalizeTag(t)))
        .filter((t) => !GENERIC_TAGS.has(normalizeTag(t)))
        .sort(cmpStr),

      references: [...new Set(allRefs.map((r) => String(r || '').trim()).filter(Boolean))].sort(cmpStr),

      locations: dedupeLocations(allLocs).sort((a, b) => {
        return cmpStr(String(a.filePath), String(b.filePath)) || (a.line ?? 0) - (b.line ?? 0) || (a.column ?? 0) - (b.column ?? 0);
      }),

      evidence: pickBestEvidence(allEvidence),
    };

    merged.push(mergedFinding);
  }

  return sortFindingsDeterministic(merged);
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
 * Derive scan completion from engine meta.
 * - COMPLETED: at least one engine ok AND none failed/timeout
 * - PARTIAL: at least one ok AND some failed/timeout
 * - FAILED: no engine ok AND at least one failed/timeout
 *
 * If engines is missing/empty, default to COMPLETED (caller can override).
 */
export function deriveScanStatus(engines?: EngineExecutionMeta[]): ScanStatus {
  const list = engines ?? [];
  if (list.length === 0) return 'COMPLETED';

  const ok = list.some((e) => e.status === 'ok');
  const bad = list.some((e) => e.status === 'failed' || e.status === 'timeout');

  if (ok && bad) return 'PARTIAL';
  if (ok && !bad) return 'COMPLETED';
  if (!ok && bad) return 'FAILED';

  // e.g., all skipped
  return 'COMPLETED';
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

  const scanStatus: ScanStatus = opts?.scanStatus ?? deriveScanStatus(opts?.engines) ?? 'COMPLETED';

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

    // back-compat alias (deprecated)
    status: gateStatus,
  };
}
