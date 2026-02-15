// packages/sarif/src/index.ts
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
  // keep MergeSafe merge context in SARIF so GitHub Code Scanning retains it
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

// POSIX separators + light normalization for stable SARIF URIs
function toSarifUri(filePath: string | undefined): string {
  const raw = String(filePath ?? '').trim();
  if (!raw) return '.';

  // normalize slashes
  let uri = raw.replace(/\\/g, '/');

  // collapse duplicate slashes (but preserve leading // if it ever occurs)
  uri = uri.replace(/([^:])\/{2,}/g, '$1/');

  // drop leading "./" for canonical display
  uri = uri.replace(/^\.\//, '');

  return uri || '.';
}

// Remove machine-specific path fragments from messages (keeps SARIF stable & portable)
function scrubMachinePaths(text: string): string {
  let s = String(text ?? '');
  s = s.replaceAll('\\', '/');

  // Windows absolute paths (C:/Users/..., D:/a/b, etc.)
  s = s.replace(/\b[A-Za-z]:\/[^\s"')]+/g, '<path>');

  // Common Unix absolute paths (/home/runner/..., /Users/..., /tmp/..., etc.)
  s = s.replace(/\b\/(home|Users|private|var|tmp|opt|etc)\/[^\s"')]+/g, '<path>');

  return s;
}

function normalizeLocations(result: SarifResult): SarifResult['locations'] {
  const fallback = [
    {
      physicalLocation: {
        artifactLocation: { uri: '.' },
        region: { startLine: 1, startColumn: 1 },
      },
    },
  ];

  if (!result.locations || result.locations.length === 0) return fallback;

  const normalized = result.locations.map((location) => {
    const uriRaw = location.physicalLocation?.artifactLocation?.uri;
    const uri = toSarifUri(uriRaw);

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

function dedupeAndSortRules(rules: SarifRule[] | undefined): SarifRule[] | undefined {
  if (!rules || rules.length === 0) return rules;

  const byId = new Map<string, SarifRule>();
  for (const r of rules) {
    const id = String(r?.id ?? '').trim();
    if (!id) continue;
    if (!byId.has(id)) byId.set(id, { ...r, id });
  }

  return Array.from(byId.values()).sort((a, b) => String(a.id).localeCompare(String(b.id)));
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
        rules: dedupeAndSortRules(driver.rules),
      },
    },
    // results order is intentionally preserved (notes first, then findings in input order)
    results: (run.results ?? []).map((r) => {
      const out: SarifResult = { ...r };
      out.locations = normalizeLocations(out);
      // normalize location URIs even if caller forgot
      if (out.locations) {
        out.locations = out.locations.map((loc) => ({
          physicalLocation: {
            artifactLocation: { uri: toSarifUri(loc.physicalLocation?.artifactLocation?.uri) },
            region: {
              startLine: Math.max(1, loc.physicalLocation?.region?.startLine ?? 1),
              startColumn: Math.max(1, loc.physicalLocation?.region?.startColumn ?? 1),
            },
          },
        }));
      }
      return out;
    }),
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
      const aKey = `${a.engineId}:${a.engineRuleId ?? ''}:${a.engineSeverity ?? ''}:${a.message ?? ''}`;
      const bKey = `${b.engineId}:${b.engineRuleId ?? ''}:${b.engineSeverity ?? ''}:${b.message ?? ''}`;
      return aKey.localeCompare(bKey);
    });
}

function stableEngineIds(finding: Finding): string[] {
  return [...new Set(stableEngineSources(finding).map((s) => s.engineId))].sort((a, b) => a.localeCompare(b));
}

// Stable rule id for merged findings (avoids churn based on which engine created findingId first)
function sarifRuleIdForFinding(finding: Finding): string {
  return `mergesafe.finding.${finding.fingerprint}`;
}

function findingToSarifResultMerged(finding: Finding, redact: boolean): SarifResult {
  const location = finding.locations?.[0];
  const engineIds = stableEngineIds(finding);
  const multi = engineIds.length > 1;

  const foundBy = engineIds.length ? engineIds.join(', ') : 'unknown';

  const safeMessageRaw = redact
    ? `${finding.title} — Found by: ${foundBy}${multi ? ' (multi-engine confirmed)' : ''}`
    : `${finding.title} — Found by: ${foundBy}${multi ? ' (multi-engine confirmed)' : ''} — ${finding.remediation}`;

  const safeMessage = scrubMachinePaths(safeMessageRaw);

  const sources = stableEngineSources(finding);
  const tags = Array.isArray(finding.tags)
    ? [...new Set(finding.tags.map((t) => String(t ?? '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b))
    : [];

  const evidenceRaw = finding.evidence
    ? {
        ...(finding.evidence.ruleId ? { ruleId: finding.evidence.ruleId } : {}),
        ...(finding.evidence.matchType ? { matchType: finding.evidence.matchType } : {}),
        ...(finding.evidence.matchSummary ? { matchSummary: finding.evidence.matchSummary } : {}),
        ...(finding.evidence.matchedSnippet ? { matchedSnippet: finding.evidence.matchedSnippet } : {}),
        ...(Array.isArray(finding.evidence.locations) && finding.evidence.locations.length
          ? { locations: finding.evidence.locations }
          : {}),
      }
    : undefined;
  const evidence = evidenceRaw && Object.keys(evidenceRaw).length > 0 ? evidenceRaw : undefined;

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
      ...(evidence ? { evidence } : {}),
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
              // PR4: URIs should be repo-relative by default (CLI should provide relative paths).
              // We still normalize slashes here to be OS-stable.
              artifactLocation: { uri: toSarifUri(location.filePath) },
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
    message: { text: scrubMachinePaths(text) },
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
    const detail = cisco.errorMessage ? ` Details: ${scrubMachinePaths(cisco.errorMessage)}` : '';
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

  // Preserve insertion order while building, but we will sort by id before output.
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

  // PR4: stable rule ordering
  const rules = Array.from(ruleMap.values()).sort((a, b) => String(a.id).localeCompare(String(b.id)));

  // PR4: stable results ordering:
  // - notes first (deterministic)
  // - then findings in input order (CLI should already stable-sort findings)
  const results: SarifResult[] = [
    ...notes.results,
    ...findings.map((f) => findingToSarifResultMerged(f, redact)),
  ];

  return normalizeRun({
    tool: {
      driver: {
        name: 'MergeSafe',
        informationUri: 'https://github.com/mergesafe/mergesafe-scanner',
        rules,
      },
    },
    results,
  });
}

export function mergeSarifRuns(args: {
  outDir: string;
  enginesMeta: EngineExecutionMeta[];
  canonicalFindings: Finding[];
  redact: boolean;
}): SarifLog {
  const { outDir, enginesMeta, canonicalFindings, redact } = args;

  // Output a single merged SARIF run so GitHub shows merged results, not duplicates per engine.
  const runs: SarifRun[] = [
    mergedFindingsRun({
      findings: canonicalFindings,
      redact,
      enginesMeta,
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
      }),
    ],
  };
}
