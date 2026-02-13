import fs from 'node:fs';
import path from 'node:path';
import { cmpNum, cmpStr, normalizeOutputPath, type EngineExecutionMeta, type Finding, type ScanResult } from '@mergesafe/core';

type SarifLevel = 'error' | 'warning' | 'note';

type SarifRule = {
  id: string;
  name?: string;
  shortDescription?: { text: string };
};

type SarifLocation = {
  physicalLocation: {
    artifactLocation: { uri?: string };
    region?: { startLine?: number; startColumn?: number; endLine?: number; endColumn?: number };
  };
};

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  fingerprints?: Record<string, string>;
  properties?: Record<string, any>;
}

interface SarifRun {
  tool: { driver: { name: string; informationUri?: string; rules?: SarifRule[] } };
  results: SarifResult[];
}

interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

const SARIF_LEVEL_RANK: Record<SarifLevel, number> = { error: 1, warning: 2, note: 3 };

function toSarifLevel(severity: string): SarifLevel {
  return severity === 'critical' || severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'note';
}

function toSarifUri(filePath: string | undefined): string {
  if (!filePath || !filePath.trim()) return '.';
  return normalizeOutputPath(filePath);
}

function compareSarifLocation(a: SarifLocation, b: SarifLocation): number {
  const aLoc = a.physicalLocation;
  const bLoc = b.physicalLocation;
  const uri = cmpStr(String(aLoc.artifactLocation.uri ?? '.'), String(bLoc.artifactLocation.uri ?? '.'));
  if (uri !== 0) return uri;
  const sl = cmpNum(Number(aLoc.region?.startLine ?? 1), Number(bLoc.region?.startLine ?? 1));
  if (sl !== 0) return sl;
  const sc = cmpNum(Number(aLoc.region?.startColumn ?? 1), Number(bLoc.region?.startColumn ?? 1));
  if (sc !== 0) return sc;
  const el = cmpNum(Number(aLoc.region?.endLine ?? aLoc.region?.startLine ?? 1), Number(bLoc.region?.endLine ?? bLoc.region?.startLine ?? 1));
  if (el !== 0) return el;
  return cmpNum(Number(aLoc.region?.endColumn ?? aLoc.region?.startColumn ?? 1), Number(bLoc.region?.endColumn ?? bLoc.region?.startColumn ?? 1));
}

function normalizeLocations(result: SarifResult): SarifLocation[] {
  const fallback: SarifLocation[] = [{
    physicalLocation: { artifactLocation: { uri: '.' }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 } },
  }];
  if (!result.locations?.length) return fallback;
  return result.locations
    .map((location) => {
      const uri = toSarifUri(location.physicalLocation?.artifactLocation?.uri);
      const region = location.physicalLocation?.region;
      const startLine = Math.max(1, region?.startLine ?? 1);
      const startColumn = Math.max(1, region?.startColumn ?? 1);
      const endLine = Math.max(startLine, region?.endLine ?? startLine);
      const endColumn = Math.max(1, region?.endColumn ?? startColumn);
      return { physicalLocation: { artifactLocation: { uri }, region: { startLine, startColumn, endLine, endColumn } } };
    })
    .sort(compareSarifLocation);
}

function dedupeRules(rules: SarifRule[] | undefined): SarifRule[] | undefined {
  if (!rules?.length) return rules;
  const byId = new Map<string, SarifRule>();
  for (const rule of rules) if (rule?.id && !byId.has(rule.id)) byId.set(rule.id, rule);
  return Array.from(byId.values()).sort((a, b) => cmpStr(String(a.id ?? ''), String(b.id ?? '')));
}

function stableEngineSources(finding: Finding) {
  const src = Array.isArray(finding.engineSources) ? finding.engineSources : [];
  return src
    .map((s) => ({
      engineId: String(s.engineId ?? '').trim(),
      engineRuleId: s.engineRuleId,
      engineSeverity: s.engineSeverity,
      message: s.message,
    }))
    .filter((s) => Boolean(s.engineId))
    .sort((a, b) => cmpStr(`${a.engineId}:${a.engineRuleId ?? ''}:${a.engineSeverity ?? ''}`, `${b.engineId}:${b.engineRuleId ?? ''}:${b.engineSeverity ?? ''}`));
}

function stableEngineIds(finding: Finding): string[] {
  return [...new Set(stableEngineSources(finding).map((s) => s.engineId))].sort((a, b) => cmpStr(a, b));
}

function sarifRuleIdForFinding(finding: Finding): string {
  return `mergesafe.finding.${finding.fingerprint}`;
}

function findingToSarifResultMerged(finding: Finding, redact: boolean): SarifResult {
  const engineIds = stableEngineIds(finding);
  const multi = engineIds.length > 1;
  const foundBy = engineIds.length ? engineIds.join(', ') : 'unknown';
  const safeMessage = redact
    ? `${finding.title} — Found by: ${foundBy}${multi ? ' (multi-engine confirmed)' : ''}`
    : `${finding.title} — Found by: ${foundBy}${multi ? ' (multi-engine confirmed)' : ''} — ${finding.remediation}`;

  const tags = Array.isArray(finding.tags)
    ? [...new Set(finding.tags.map((t) => String(t ?? '').trim()).filter(Boolean))].sort((a, b) => cmpStr(a, b))
    : [];

  const result: SarifResult = {
    ruleId: sarifRuleIdForFinding(finding),
    level: toSarifLevel(finding.severity),
    message: { text: safeMessage },
    locations: finding.locations?.map((location) => ({
      physicalLocation: {
        artifactLocation: { uri: toSarifUri(location.filePath) },
        region: { startLine: Math.max(1, location.line ?? 1), startColumn: Math.max(1, location.column ?? 1) },
      },
    })),
    fingerprints: { primaryLocationLineHash: finding.fingerprint },
    properties: {
      mergesafe: {
        findingId: finding.findingId,
        fingerprint: finding.fingerprint,
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        owaspMcpTop10: finding.owaspMcpTop10,
        tags,
        multiEngineConfirmed: multi,
        engineSources: stableEngineSources(finding),
      },
    },
  };

  result.locations = normalizeLocations(result);
  return result;
}

function makeNoteResult(ruleId: string, text: string): SarifResult {
  return { ruleId, level: 'note', message: { text }, locations: normalizeLocations({ ruleId, level: 'note', message: { text } }) };
}

function engineStatusNotes(enginesMeta: EngineExecutionMeta[] | undefined): { rules: SarifRule[]; results: SarifResult[] } {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  if (!enginesMeta?.length) return { rules, results };
  const cisco = enginesMeta.find((e) => e.engineId === 'cisco');
  if (!cisco) return { rules, results };

  const ruleId = 'mergesafe.engine.cisco.note';
  rules.push({ id: ruleId, name: 'Cisco MCP scanner execution note', shortDescription: { text: 'Cisco runs offline-safe by default; known-configs scans local MCP client configs.' } });

  if (cisco.status === 'ok') {
    results.push(makeNoteResult(ruleId, 'Cisco ran in offline-safe mode. It may have scanned MCP client configs from known locations on this machine (Cursor/Windsurf/VS Code, etc.), not necessarily repo source. Validate relevance to the project.'));
  } else if (cisco.status === 'skipped') {
    results.push(makeNoteResult(ruleId, 'Cisco was skipped (offline-safe default). To scan deterministically with Cisco, provide tools JSON (static mode) e.g. --cisco-tools <tools-list.json>, or run on a machine where MCP client configs are discoverable.'));
  } else if (cisco.status === 'failed' || cisco.status === 'timeout') {
    const detail = cisco.errorMessage ? ` Details: ${cisco.errorMessage}` : '';
    results.push(makeNoteResult(ruleId, `Cisco failed to run.${detail} This does not fail the overall MergeSafe scan unless you explicitly require it.`));
  }

  return { rules, results };
}

function normalizeRun(run: SarifRun): SarifRun {
  return {
    ...run,
    tool: { ...run.tool, driver: { ...run.tool.driver, rules: dedupeRules(run.tool.driver.rules) } },
    results: run.results
      .map((result) => ({ ...result, locations: normalizeLocations(result) }))
      .sort((a, b) => {
        const level = cmpNum(SARIF_LEVEL_RANK[a.level] ?? 99, SARIF_LEVEL_RANK[b.level] ?? 99);
        if (level !== 0) return level;
        const rule = cmpStr(String(a.ruleId ?? ''), String(b.ruleId ?? ''));
        if (rule !== 0) return rule;
        const primary = compareSarifLocation(a.locations?.[0] ?? normalizeLocations(a)[0], b.locations?.[0] ?? normalizeLocations(b)[0]);
        if (primary !== 0) return primary;
        const fp = cmpStr(String(a.fingerprints?.primaryLocationLineHash ?? ''), String(b.fingerprints?.primaryLocationLineHash ?? ''));
        if (fp !== 0) return fp;
        return cmpStr(String(a.message?.text ?? ''), String(b.message?.text ?? ''));
      }),
  };
}

function mergedFindingsRun(args: { findings: Finding[]; redact: boolean; enginesMeta?: EngineExecutionMeta[] }): SarifRun {
  const { findings, redact, enginesMeta } = args;
  const notes = engineStatusNotes(enginesMeta);
  const ruleMap = new Map<string, SarifRule>();

  for (const f of findings) {
    const id = sarifRuleIdForFinding(f);
    if (!ruleMap.has(id)) ruleMap.set(id, { id, name: f.title, shortDescription: { text: f.title } });
  }
  for (const rule of notes.rules) if (rule?.id && !ruleMap.has(rule.id)) ruleMap.set(rule.id, rule);
  for (const result of notes.results) {
    if (result?.ruleId && !ruleMap.has(result.ruleId)) {
      ruleMap.set(result.ruleId, { id: result.ruleId, name: result.ruleId, shortDescription: { text: result.ruleId } });
    }
  }

  return normalizeRun({
    tool: { driver: { name: 'MergeSafe', informationUri: 'https://github.com/mergesafe/mergesafe-scanner', rules: Array.from(ruleMap.values()) } },
    results: [...notes.results, ...findings.map((f) => findingToSarifResultMerged(f, redact))],
  });
}

export function mergeSarifRuns(args: { outDir: string; enginesMeta: EngineExecutionMeta[]; canonicalFindings: Finding[]; redact: boolean }): SarifLog {
  const { outDir, enginesMeta, canonicalFindings, redact } = args;
  const log: SarifLog = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [mergedFindingsRun({ findings: canonicalFindings, redact, enginesMeta })],
  };
  fs.mkdirSync(path.resolve(outDir), { recursive: true });
  fs.writeFileSync(path.join(path.resolve(outDir), 'results.sarif'), JSON.stringify(log, null, 2));
  return log;
}

export function toSarif(result: ScanResult): SarifLog {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [mergedFindingsRun({ findings: result.findings, redact: result.meta.redacted, enginesMeta: result.meta.engines })],
  };
}
