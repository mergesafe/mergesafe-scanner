import type { ScanResult } from '@mergesafe/core';

export function generateSummaryMarkdown(result: ScanResult): string {
  const top = result.findings.slice(0, 10).map((f) => `- **${f.severity.toUpperCase()}** ${f.title} (${f.locations[0]?.filePath}:${f.locations[0]?.line})`).join('\n');
  return `# MergeSafe Summary\n\nStatus: **${result.summary.status}**\n\nGrade: **${result.summary.grade}** (score ${result.summary.score})\n\n## Totals\n- Total findings: ${result.summary.totalFindings}\n- Critical: ${result.summary.bySeverity.critical}\n- High: ${result.summary.bySeverity.high}\n- Medium: ${result.summary.bySeverity.medium}\n- Low: ${result.summary.bySeverity.low}\n\n## Top Findings\n${top || '- None'}\n`;
}

export function generateHtmlReport(result: ScanResult): string {
  const rows = result.findings.map((f, i) => `<tr><td>${i + 1}</td><td>${f.severity}</td><td>${f.title}</td><td>${f.locations[0]?.filePath}:${f.locations[0]?.line}</td><td><details><summary>Details</summary><p>${f.remediation}</p><pre>${f.evidence.excerpt ?? f.evidence.excerptHash}</pre></details></td></tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>MergeSafe Report</title><style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;text-align:left}.badge{padding:4px 8px;border-radius:4px;background:#222;color:#fff}</style></head><body><h1>MergeSafe Report</h1><p><span class="badge">${result.summary.status}</span> Grade ${result.summary.grade} / Score ${result.summary.score}</p><p>Engine matrix: MergeSafe</p><table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Location</th><th>Remediation</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}
