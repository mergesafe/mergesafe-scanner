import type { ScanResult } from '@mergesafe/core';

export function toSarif(result: ScanResult) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'MergeSafe',
            informationUri: 'https://github.com/mergesafe/mergesafe-scanner',
            rules: result.findings.map((f) => ({ id: f.engineSources[0]?.ruleId ?? f.findingId, name: f.title, shortDescription: { text: f.title } })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.engineSources[0]?.ruleId ?? f.findingId,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
          message: { text: `${f.title} - ${f.remediation}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: f.locations[0]?.filePath }, region: { startLine: f.locations[0]?.line ?? 1 } } }],
          fingerprints: { primaryLocationLineHash: f.fingerprint },
        })),
      },
    ],
  };
}
