import fs from 'node:fs';
import path from 'node:path';
import type { EngineExecutionMeta, Finding, ScanResult } from '@mergesafe/core';

type SarifLevel = 'error' | 'warning' | 'note';

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
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri?: string;
      rules?: Array<{ id: string; name?: string; shortDescription?: { text: string } }>;
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
  return severity === 'critical' || severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'note';
}

function findingToSarifResult(finding: Finding, engineId: string, redact: boolean): SarifResult {
  const source = finding.engineSources.find((entry) => entry.engineId === engineId) ?? finding.engineSources[0];
  const location = finding.locations[0];
  const safeMessage = redact
    ? `${finding.title} (${engineId})`
    : `${finding.title} (${engineId}) - ${finding.remediation}`;

  return {
    ruleId: source?.engineRuleId ?? finding.findingId,
    level: toSarifLevel(finding.severity),
    message: { text: safeMessage },
    locations: location
      ? [{
          physicalLocation: {
            artifactLocation: { uri: location.filePath },
            region: { startLine: location.line ?? 1, startColumn: location.column },
          },
        }]
      : undefined,
    fingerprints: { primaryLocationLineHash: finding.fingerprint },
  };
}

function findingsRun(engineId: string, displayName: string, findings: Finding[], redact: boolean): SarifRun {
  const rules = findings.map((finding) => {
    const source = finding.engineSources.find((entry) => entry.engineId === engineId) ?? finding.engineSources[0];
    return {
      id: source?.engineRuleId ?? finding.findingId,
      name: finding.title,
      shortDescription: { text: finding.title },
    };
  });

  return {
    tool: {
      driver: {
        name: engineId === 'mergesafe' ? 'MergeSafe' : displayName,
        informationUri: engineId === 'mergesafe' ? 'https://github.com/mergesafe/mergesafe-scanner' : undefined,
        rules,
      },
    },
    results: findings.map((finding) => findingToSarifResult(finding, engineId, redact)),
  };
}

function parseSarifRuns(filePath: string): SarifRun[] {
  if (!fs.existsSync(filePath)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as { runs?: SarifRun[] };
    return Array.isArray(parsed.runs) ? parsed.runs : [];
  } catch {
    return [];
  }
}

export function mergeSarifRuns(args: { outDir: string; enginesMeta: EngineExecutionMeta[]; canonicalFindings: Finding[]; redact: boolean }): SarifLog {
  const { outDir, enginesMeta, canonicalFindings, redact } = args;
  const runs: SarifRun[] = [];

  const findingsByEngine = new Map<string, Finding[]>();
  for (const finding of canonicalFindings) {
    for (const source of finding.engineSources) {
      const list = findingsByEngine.get(source.engineId) ?? [];
      list.push(finding);
      findingsByEngine.set(source.engineId, list);
    }
  }

  const allEngineIds = new Set<string>(['mergesafe', ...enginesMeta.map((entry) => entry.engineId), ...findingsByEngine.keys()]);

  for (const engineId of allEngineIds) {
    const meta = enginesMeta.find((entry) => entry.engineId === engineId);
    const importedRuns = meta?.artifacts?.sarif ? parseSarifRuns(meta.artifacts.sarif) : [];

    if (importedRuns.length > 0) {
      runs.push(...importedRuns);
      continue;
    }

    const findings = findingsByEngine.get(engineId) ?? [];
    const displayName = meta?.displayName ?? engineId;
    runs.push(findingsRun(engineId, displayName, findings, redact));
  }

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
    runs: [findingsRun('mergesafe', 'MergeSafe', result.findings, result.meta.redacted)],
  };
}
