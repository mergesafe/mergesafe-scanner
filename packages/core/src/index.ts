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

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  score: number;
  grade: 'A'|'B'|'C'|'D'|'F';
  status: 'PASS'|'FAIL';
}

export interface EngineExecutionMeta {
  engineId: string;
  version: string;
  status: 'ok' | 'skipped' | 'failed' | 'timeout';
  durationMs: number;
  errorMessage?: string;
  installHint?: string;
}

export interface ScanMeta {
  scannedPath: string;
  generatedAt: string;
  mode: 'fast'|'deep';
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

export interface CliConfig {
  outDir: string;
  format: string[];
  mode: 'fast'|'deep';
  timeout: number;
  concurrency: number;
  failOn: 'critical'|'high'|'none';
  redact: boolean;
  autoInstall: boolean;
  engines?: string[];
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

export function stableHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

export function lineBucket(line: number): number {
  return Math.floor(Math.max(line, 1) / 5) * 5;
}

export function findingFingerprint(filePath: string, line: number, evidence: string): string {
  return stableHash(`${filePath}:${lineBucket(line)}:${stableHash(evidence)}`);
}

export function toFinding(raw: RawFinding, redact: boolean): Finding {
  const snippetHash = stableHash(raw.evidence);
  const fingerprint = findingFingerprint(raw.filePath, raw.line, raw.evidence);
  return {
    findingId: `${raw.ruleId}-${fingerprint}`,
    title: raw.title,
    severity: raw.severity,
    confidence: raw.confidence,
    category: raw.category,
    owaspMcpTop10: raw.owaspMcpTop10,
    engineSources: [{ engineId: 'mergesafe', engineRuleId: raw.ruleId, engineSeverity: raw.severity, message: raw.title }],
    locations: [{ filePath: raw.filePath, line: raw.line }],
    evidence: redact ? { excerptHash: snippetHash, note: 'Redacted evidence' } : { excerpt: raw.evidence, note: 'Static pattern match' },
    remediation: raw.remediation,
    references: raw.references,
    tags: raw.tags,
    fingerprint,
  };
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

export function mergeCanonicalFindings(findings: Finding[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = map.get(finding.fingerprint);
    if (!existing) {
      map.set(finding.fingerprint, {
        ...finding,
        locations: [...finding.locations],
        engineSources: [...finding.engineSources],
        references: [...finding.references],
        tags: [...finding.tags],
      });
      continue;
    }
    existing.locations.push(...finding.locations);
    existing.engineSources.push(...finding.engineSources);
    existing.references = [...new Set([...existing.references, ...finding.references])];
    existing.tags = [...new Set([...existing.tags, ...finding.tags])];
  }
  return [...map.values()].map((finding) => ({
    ...finding,
    engineSources: finding.engineSources.filter((source, index, arr) => {
      const key = `${source.engineId}:${source.engineRuleId ?? ''}:${source.message ?? ''}`;
      return arr.findIndex((candidate) => `${candidate.engineId}:${candidate.engineRuleId ?? ''}:${candidate.message ?? ''}` === key) === index;
    }),
  }));
}

export function summarize(findings: Finding[], failOn: CliConfig['failOn']): ScanSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;
  let score = 100 - bySeverity.critical * 30 - bySeverity.high * 15 - bySeverity.medium * 7 - bySeverity.low * 2;
  score = Math.max(0, score);
  const grade: ScanSummary['grade'] = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
  const status = shouldFail(bySeverity, failOn) ? 'FAIL' : 'PASS';
  return { totalFindings: findings.length, bySeverity, score, grade, status };
}

export function shouldFail(bySeverity: Record<Severity, number>, failOn: CliConfig['failOn']): boolean {
  if (failOn === 'none') return false;
  if (failOn === 'critical') return bySeverity.critical > 0;
  return bySeverity.critical > 0 || bySeverity.high > 0;
}
