import type { Finding, ScanResult } from '@mergesafe/core';

const severityRank: Record<Finding['severity'], number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const confidenceRank: Record<Finding['confidence'], number> = { high: 3, medium: 2, low: 1 };

export function generateSummaryMarkdown(result: ScanResult): string {
  const top = [...result.findings]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || confidenceRank[b.confidence] - confidenceRank[a.confidence])
    .slice(0, 5)
    .map((f) => `- **${f.severity.toUpperCase()}** ${f.title} (${f.locations[0]?.filePath}:${f.locations[0]?.line})`)
    .join('\n');
  const engineLine = (result.meta.engines ?? []).map((entry) => `${entry.engineId}:${entry.status}`).join(', ') || 'mergesafe:ok';
  return `# MergeSafe Summary\n\nStatus: **${result.summary.status}**\n\nGrade: **${result.summary.grade}** (score ${result.summary.score})\n\n## Totals\n- Total findings: ${result.summary.totalFindings}\n- Critical: ${result.summary.bySeverity.critical}\n- High: ${result.summary.bySeverity.high}\n- Medium: ${result.summary.bySeverity.medium}\n- Low: ${result.summary.bySeverity.low}\n- Info: ${result.summary.bySeverity.info}\n\n## Engines\n- ${engineLine}\n\n## Top Findings\n${top || '- None'}\n`;
}

export function generateHtmlReport(result: ScanResult): string {
  const engineRows = (result.meta.engines ?? []).map((entry) => `<tr><td>${entry.engineId}</td><td>${entry.version}</td><td>${entry.status}</td><td>${entry.durationMs}</td></tr>`).join('');
  const rows = result.findings.map((f, i) => `<tr><td>${i + 1}</td><td>${f.severity}</td><td>${f.title}</td><td>${f.locations[0]?.filePath}:${f.locations[0]?.line}</td><td><details><summary>Details</summary><p>${f.remediation}</p><pre>${f.evidence.excerpt ?? f.evidence.excerptHash}</pre><p>Engine matrix:</p><ul>${f.engineSources.map((source) => `<li>${source.engineId} / ${source.engineRuleId ?? '-'} / ${source.engineSeverity ?? '-'}</li>`).join('')}</ul></details></td></tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>MergeSafe Report</title><style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;text-align:left}.badge{padding:4px 8px;border-radius:4px;background:#222;color:#fff}</style></head><body><h1>MergeSafe Report</h1><p><span class="badge">${result.summary.status}</span> Grade ${result.summary.grade} / Score ${result.summary.score}</p><h2>Engines</h2><table><thead><tr><th>Engine</th><th>Version</th><th>Status</th><th>Duration (ms)</th></tr></thead><tbody>${engineRows}</tbody></table><h2>Findings</h2><table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Location</th><th>Remediation</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}
