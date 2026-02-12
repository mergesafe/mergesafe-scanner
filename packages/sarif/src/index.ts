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
      region?: { startLine?: number; startColumn?: number };
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

// Keep URIs stable across Windows/macOS/Linux
function toSarifUri(filePath: string | undefined, uriBaseDir?: string): string {
  if (!filePath || !filePath.trim()) return '.';
  const normalized = filePath.replace(/\\/g, '/');
  if (!uriBaseDir) return normalized;

  const absBase = path.resolve(uriBaseDir);
  const absPath = path.isAbsolute(filePath) ? path.resolve(filePath) : path.resolve(absBase, filePath);
  const rel = path.relative(absBase, absPath);
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) return rel.replace(/\\/g, '/');
  return normalized;
}


function normalizeLocations(result: SarifResult): SarifResult['locations'] {
  const fallback = [{
    physicalLocation: {
      artifactLocation: { uri: '.' },
      region: { startLine: 1, startColumn: 1 },
    },
  }];

  if (!result.locations || result.locations.length === 0) return fallback;

  const normalized = result.locations.map((location) => {
    const uri = location.physicalLocation?.artifactLocation?.uri?.trim()
      ? location.physicalLocation.artifactLocation.uri
      : '.';

    const startLine = Math.max(1, location.physicalLocation?.region?.startLine ?? 1);
    const startColumn = Math.max(1, location.physicalLocation?.region?.startColumn ?? 1);

    return {
      physicalLocation: {
        artifactLocation: { uri },
        region: { startLine, startColumn },
      },
    };
  });

  return normalized.length > 0 ? normalized : fallback;
}

function dedupeRules(rules: SarifRule[] | undefined): SarifRule[] | undefined {
  if (!rules || rules.length === 0) return rules;

  const byId = new Map<string, SarifRule>();
  for (const r of rules) {
    if (!r?.id) continue;
    if (!byId.has(r.id)) byId.set(r.id, r);
  }
  return Array.from(byId.values());
}

function normalizeRun(run: SarifRun): SarifRun {
  const driver = run?.tool?.driver;
  if (!driver) return run;

  return {
    ...run,
    tool: {
      ...run.tool,
      driver: {
        ...driver,
        rules: dedupeRules(driver.rules),
      },
    },
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
      return aKey.localeCompare(bKey);
    });
}

function stableEngineIds(finding: Finding): string[] {
  return [...new Set(stableEngineSources(finding).map((s) => s.engineId))].sort((a, b) => a.localeCompare(b));
}

// ✅ Stable rule id for merged findings (avoids churn based on which engine created findingId first)
function sarifRuleIdForFinding(finding: Finding): string {
  return `mergesafe.finding.${finding.fingerprint}`;
}

function findingToSarifResultMerged(finding: Finding, redact: boolean, uriBaseDir?: string): SarifResult {
  const location = finding.locations?.[0];
  const engineIds = stableEngineIds(finding);
  const multi = engineIds.length > 1;

  const foundBy = engineIds.length ? engineIds.join(', ') : 'unknown';

  const safeMessage = redact
    ? `${finding.title} — Found by: ${foundBy}${multi ? ' (multi-engine confirmed)' : ''}`
    : `${finding.title} — Found by: ${foundBy}${multi ? ' (multi-engine confirmed)' : ''} — ${finding.remediation}`;

  const sources = stableEngineSources(finding);
  const tags = Array.isArray(finding.tags)
    ? [...new Set(finding.tags.map((t) => String(t ?? '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b))
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

  const result: SarifResult = {
    ruleId: sarifRuleIdForFinding(finding),
    level: toSarifLevel(finding.severity),
    message: { text: safeMessage },
    locations: location
      ? [
          {
            physicalLocation: {
              artifactLocation: { uri: toSarifUri(location.filePath, uriBaseDir) },
              region: { startLine: Math.max(1, location.line ?? 1), startColumn: Math.max(1, location.column ?? 1) },
            },
          },
        ]
      : undefined,
    fingerprints: { primaryLocationLineHash: finding.fingerprint },
    properties: props,
  };

  result.locations = normalizeLocations(result);
  return result;
}

function makeNoteResult(ruleId: string, text: string): SarifResult {
  const result: SarifResult = {
    ruleId,
    level: 'note',
    message: { text },
  };
  result.locations = normalizeLocations(result);
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
  uriBaseDir?: string;
}): SarifRun {
  const { findings, redact, enginesMeta, uriBaseDir } = args;

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

  const rules = Array.from(ruleMap.values()).sort((a, b) => a.id.localeCompare(b.id));

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
      ...findings.map((f) => findingToSarifResultMerged(f, redact, uriBaseDir)),
    ].sort((a, b) => {
      const aUri = a.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '';
      const bUri = b.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '';
      const byUri = aUri.localeCompare(bUri);
      if (byUri !== 0) return byUri;
      const aLine = a.locations?.[0]?.physicalLocation?.region?.startLine ?? 0;
      const bLine = b.locations?.[0]?.physicalLocation?.region?.startLine ?? 0;
      if (aLine !== bLine) return aLine - bLine;
      return String(a.ruleId).localeCompare(String(b.ruleId));
    }),
  });
}

export function mergeSarifRuns(args: {
  outDir: string;
  enginesMeta: EngineExecutionMeta[];
  canonicalFindings: Finding[];
  redact: boolean;
  uriBaseDir?: string;
}): SarifLog {
  const { outDir, enginesMeta, canonicalFindings, redact, uriBaseDir } = args;

  // ✅ IMPORTANT: Output a single merged SARIF run so GitHub shows merged results, not duplicates per engine.
  const runs: SarifRun[] = [
    mergedFindingsRun({
      findings: canonicalFindings,
      redact,
      enginesMeta,
      uriBaseDir,
    }),
  ];

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
        uriBaseDir: process.cwd(),
      }),
    ],
  };
}
