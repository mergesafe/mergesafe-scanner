import fs from 'node:fs';
import path from 'node:path';
import type { EngineExecutionMeta, Finding, ScanResult } from '@mergesafe/core';

type SarifLevel = 'error' | 'warning' | 'note';

type SarifRule = {
  id: string;
  name?: string;
  shortDescription?: { text: string };
};

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri?: string };
      region?: { startLine?: number; startColumn?: number; endLine?: number; endColumn?: number };
    };
  }>;
  fingerprints?: Record<string, string>;
  // ✅ Step 5: keep merge context in SARIF so GitHub Code Scanning retains it
  properties?: Record<string, any>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri?: string;
      rules?: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

function toSarifLevel(severity: string): SarifLevel {
  return severity === 'critical' || severity === 'high'
    ? 'error'
    : severity === 'medium'
      ? 'warning'
      : 'note';
}

/**
 * IMPORTANT: Keep URIs stable across Windows/macOS/Linux.
 * - Never use path.normalize() for output URIs (it reintroduces '\' on Windows).
 * - Always output '/' separators in SARIF.
 */
function toSarifUri(filePath: string | undefined): string {
  if (!filePath || !filePath.trim()) return '.';
  return filePath.trim().replace(/\\/g, '/');
}

/** Stable, locale-independent compare helpers */
function cmpStr(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}
function cmpNum(a: number, b: number): number {
  return a === b ? 0 : a < b ? -1 : 1;
}

function levelRank(level: SarifLevel | undefined): number {
  // Explicit rank (don’t rely on lexicographic order)
  // error (0) < warning (1) < note (2)
  if (level === 'error') return 0;
  if (level === 'warning') return 1;
  return 2;
}

type SarifLocation = NonNullable<SarifResult['locations']>[number];

function locationKey(loc: SarifLocation): string {
  const pl = loc?.physicalLocation;
  const uri = toSarifUri(pl?.artifactLocation?.uri);
  const r = pl?.region ?? {};
  const sl = Number(r.startLine ?? 1);
  const sc = Number(r.startColumn ?? 1);
  const el = Number(r.endLine ?? 0);
  const ec = Number(r.endColumn ?? 0);
  // Use separators that won’t collide with file names
  return `${uri}\u0000${sl}\u0000${sc}\u0000${el}\u0000${ec}`;
}

/**
 * Normalize + deterministically sort locations.
 * This fixes your current CI mismatch where the *same* locations appear but in different orders.
 */
function normalizeLocations(locations: SarifResult['locations'] | undefined): SarifResult['locations'] {
  const fallback: SarifLocation[] = [
    {
      physicalLocation: {
        artifactLocation: { uri: '.' },
        region: { startLine: 1, startColumn: 1 },
      },
    },
  ];

  const locs = Array.isArray(locations) ? locations : [];
  if (locs.length === 0) return fallback;

  const normalized: SarifLocation[] = locs.map((location) => {
    const pl = location?.physicalLocation;

    const uri = toSarifUri(pl?.artifactLocation?.uri);
    const region = pl?.region ?? {};

    const startLine = Math.max(1, Number(region.startLine ?? 1));
    const startColumn = Math.max(1, Number(region.startColumn ?? 1));
    const endLine = region.endLine != null ? Math.max(1, Number(region.endLine)) : undefined;
    const endColumn = region.endColumn != null ? Math.max(1, Number(region.endColumn)) : undefined;

    return {
      physicalLocation: {
        artifactLocation: { uri: uri || '.' },
        region: {
          startLine,
          startColumn,
          ...(endLine != null ? { endLine } : {}),
          ...(endColumn != null ? { endColumn } : {}),
        },
      },
    };
  });

  normalized.sort((a, b) => cmpStr(locationKey(a), locationKey(b)));
  return normalized.length > 0 ? normalized : fallback;
}

function dedupeRules(rules: SarifRule[] | undefined): SarifRule[] | undefined {
  if (!rules || rules.length === 0) return rules;

  const byId = new Map<string, SarifRule>();
  for (const r of rules) {
    if (!r?.id) continue;
    if (!byId.has(r.id)) byId.set(r.id, r);
  }

  // Stable rule order
  return Array.from(byId.values()).sort((a, b) => cmpStr(String(a.id), String(b.id)));
}

function primaryLocationKey(result: SarifResult): string {
  const loc = result.locations?.[0];
  if (!loc) return '.\u00001\u00001\u00000\u00000';
  return locationKey(loc as SarifLocation);
}

/**
 * Deterministic run normalization:
 * - stable rules ordering
 * - stable locations ordering inside each result
 * - stable results ordering using explicit ranking, NOT localeCompare()
 */
function normalizeRun(run: SarifRun): SarifRun {
  const driver = run?.tool?.driver;
  if (!driver) return run;

  const normalizedResults = (run.results ?? []).map((r) => {
    const out: SarifResult = { ...r };
    out.locations = normalizeLocations(out.locations);
    return out;
  });

  normalizedResults.sort((a, b) => {
    // 1) severity rank
    const ra = levelRank(a.level);
    const rb = levelRank(b.level);
    const rcmp = cmpNum(ra, rb);
    if (rcmp !== 0) return rcmp;

    // 2) ruleId (stable)
    const rid = cmpStr(String(a.ruleId ?? ''), String(b.ruleId ?? ''));
    if (rid !== 0) return rid;

    // 3) primary location (uri/line/col)
    const pl = cmpStr(primaryLocationKey(a), primaryLocationKey(b));
    if (pl !== 0) return pl;

    // 4) fingerprint tie-break (prevents nondeterminism when everything else matches)
    const fa = String(a.fingerprints?.primaryLocationLineHash ?? '');
    const fb = String(b.fingerprints?.primaryLocationLineHash ?? '');
    const fcmp = cmpStr(fa, fb);
    if (fcmp !== 0) return fcmp;

    // 5) message tie-break (last resort)
    return cmpStr(String(a.message?.text ?? ''), String(b.message?.text ?? ''));
  });

  return {
    ...run,
    tool: {
      ...run.tool,
      driver: {
        ...driver,
        rules: dedupeRules(driver.rules),
      },
    },
    results: normalizedResults,
  };
}

function stableEngineSources(finding: Finding): Array<{
  engineId: string;
  engineRuleId?: string;
  engineSeverity?: string;
  message?: string;
}> {
  const src = Array.isArray(finding.engineSources) ? finding.engineSources : [];
  return src
    .map((s) => ({
      engineId: String(s.engineId ?? '').trim(),
      engineRuleId: s.engineRuleId,
      engineSeverity: s.engineSeverity,
      message: s.message,
    }))
    .filter((s) => Boolean(s.engineId))
    .sort((a, b) => {
      const aKey = `${a.engineId}:${a.engineRuleId ?? ''}:${a.engineSeverity ?? ''}`;
      const bKey = `${b.engineId}:${b.engineRuleId ?? ''}:${b.engineSeverity ?? ''}`;
      return cmpStr(aKey, bKey);
    });
}

function stableEngineIds(finding: Finding): string[] {
  return [...new Set(stableEngineSources(finding).map((s) => s.engineId))].sort((a, b) => cmpStr(a, b));
}

// ✅ Stable rule id for merged findings (avoids churn)
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

  const sources = stableEngineSources(finding);
  const tags = Array.isArray(finding.tags)
    ? [...new Set(finding.tags.map((t) => String(t ?? '').trim()).filter(Boolean))].sort((a, b) => cmpStr(a, b))
    : [];

  const props = {
    mergesafe: {
      findingId: finding.findingId,
      fingerprint: finding.fingerprint,
      severity: finding.severity,
      confidence: finding.confidence,
      category: finding.category,
      owaspMcpTop10: finding.owaspMcpTop10,
      tags,
      multiEngineConfirmed: multi,
      engineSources: sources,
    },
  };

  // ✅ IMPORTANT: include ALL finding locations (not just [0]) then normalize+sort deterministically.
  const locs = Array.isArray(finding.locations) ? finding.locations : [];

  const result: SarifResult = {
    ruleId: sarifRuleIdForFinding(finding),
    level: toSarifLevel(finding.severity),
    message: { text: safeMessage },
    locations: locs.length
      ? locs.map((l) => ({
          physicalLocation: {
            artifactLocation: { uri: toSarifUri(l.filePath) },
            region: {
              startLine: Math.max(1, Number(l.line ?? 1)),
              startColumn: Math.max(1, Number(l.column ?? 1)),
            },
          },
        }))
      : undefined,
    fingerprints: { primaryLocationLineHash: finding.fingerprint },
    properties: props,
  };

  result.locations = normalizeLocations(result.locations);
  return result;
}

function makeNoteResult(ruleId: string, text: string): SarifResult {
  const result: SarifResult = {
    ruleId,
    level: 'note',
    message: { text },
  };
  result.locations = normalizeLocations(result.locations);
  return result;
}

function engineStatusNotes(enginesMeta: EngineExecutionMeta[] | undefined): { rules: SarifRule[]; results: SarifResult[] } {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];

  if (!enginesMeta || enginesMeta.length === 0) return { rules, results };

  const cisco = enginesMeta.find((e) => e.engineId === 'cisco');
  if (!cisco) return { rules, results };

  const ruleId = 'mergesafe.engine.cisco.note';
  rules.push({
    id: ruleId,
    name: 'Cisco MCP scanner execution note',
    shortDescription: { text: 'Cisco runs offline-safe by default; known-configs scans local MCP client configs.' },
  });

  if (cisco.status === 'ok') {
    results.push(
      makeNoteResult(
        ruleId,
        'Cisco ran in offline-safe mode. It may have scanned MCP client configs from known locations on this machine (Cursor/Windsurf/VS Code, etc.), not necessarily repo source. Validate relevance to the project.'
      )
    );
  } else if (cisco.status === 'skipped') {
    results.push(
      makeNoteResult(
        ruleId,
        'Cisco was skipped (offline-safe default). To scan deterministically with Cisco, provide tools JSON (static mode) e.g. --cisco-tools <tools-list.json>, or run on a machine where MCP client configs are discoverable.'
      )
    );
  } else if (cisco.status === 'failed' || cisco.status === 'timeout') {
    const detail = cisco.errorMessage ? ` Details: ${cisco.errorMessage}` : '';
    results.push(
      makeNoteResult(
        ruleId,
        `Cisco failed to run.${detail} This does not fail the overall MergeSafe scan unless you explicitly require it.`
      )
    );
  }

  return { rules, results };
}

function mergedFindingsRun(args: {
  findings: Finding[];
  redact: boolean;
  enginesMeta?: EngineExecutionMeta[];
}): SarifRun {
  const { findings, redact, enginesMeta } = args;

  const notes = engineStatusNotes(enginesMeta);

  // Rules: one per merged finding (stable id), plus note rule(s)
  const ruleMap = new Map<string, SarifRule>();

  for (const f of findings) {
    const id = sarifRuleIdForFinding(f);
    if (!ruleMap.has(id)) {
      ruleMap.set(id, {
        id,
        name: f.title,
        shortDescription: { text: f.title },
      });
    }
  }

  for (const r of notes.rules) {
    if (r?.id && !ruleMap.has(r.id)) ruleMap.set(r.id, r);
  }

  // Ensure rule exists for each note result
  for (const r of notes.results) {
    if (!r?.ruleId) continue;
    if (!ruleMap.has(r.ruleId)) {
      ruleMap.set(r.ruleId, {
        id: r.ruleId,
        name: r.ruleId,
        shortDescription: { text: r.ruleId },
      });
    }
  }

  const rules = Array.from(ruleMap.values());

  return normalizeRun({
    tool: {
      driver: {
        name: 'MergeSafe',
        informationUri: 'https://github.com/mergesafe/mergesafe-scanner',
        rules,
      },
    },
    results: [
      ...notes.results,
      // stable input ordering; normalizeRun will apply final deterministic ordering
      ...[...findings]
        .sort((a, b) => cmpStr(String(a.fingerprint ?? ''), String(b.fingerprint ?? '')))
        .map((f) => findingToSarifResultMerged(f, redact)),
    ],
  });
}

export function mergeSarifRuns(args: {
  outDir: string;
  enginesMeta: EngineExecutionMeta[];
  canonicalFindings: Finding[];
  redact: boolean;
}): SarifLog {
  const { outDir, enginesMeta, canonicalFindings, redact } = args;

  const runs: SarifRun[] = [
    mergedFindingsRun({
      findings: canonicalFindings,
      redact,
      enginesMeta,
    }),
  ].sort((a, b) => cmpStr(String(a.tool.driver.name), String(b.tool.driver.name)));

  const log: SarifLog = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs,
  };

  fs.mkdirSync(path.resolve(outDir), { recursive: true });
  fs.writeFileSync(path.join(path.resolve(outDir), 'results.sarif'), JSON.stringify(log, null, 2));
  return log;
}

export function toSarif(result: ScanResult): SarifLog {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      mergedFindingsRun({
        findings: result.findings,
        redact: result.meta.redacted,
        enginesMeta: result.meta.engines,
      }),
    ].sort((a, b) => cmpStr(String(a.tool.driver.name), String(b.tool.driver.name))),
  };
}
