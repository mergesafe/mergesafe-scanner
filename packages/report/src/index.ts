import type { Finding, ScanResult } from '@mergesafe/core';

const severityRank: Record<Finding['severity'], number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const confidenceRank: Record<Finding['confidence'], number> = { high: 3, medium: 2, low: 1 };

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function topFindings(result: ScanResult): Finding[] {
  return [...result.findings]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || confidenceRank[b.confidence] - confidenceRank[a.confidence])
    .slice(0, 5);
}

export function generateSummaryMarkdown(result: ScanResult): string {
  const engineRows = (result.meta.engines ?? [])
    .map((entry) => `| ${entry.displayName} (${entry.engineId}) | ${entry.version} | ${entry.status} | ${entry.durationMs} | ${entry.errorMessage ?? entry.installHint ?? '-'} |`)
    .join('\n');

  const top = topFindings(result)
    .map((f) => {
      const attribution = [...new Set(f.engineSources.map((source) => source.engineId))].join(', ');
      return `- **${f.severity.toUpperCase()}** ${f.title} (${f.locations[0]?.filePath}:${f.locations[0]?.line}) — flagged by: ${attribution}`;
    })
    .join('\n');

  return `# MergeSafe Summary\n\nStatus: **${result.summary.status}**\n\nGrade: **${result.summary.grade}** (score ${result.summary.score})\n\n## Totals\n- Total findings: ${result.summary.totalFindings}\n- Critical: ${result.summary.bySeverity.critical}\n- High: ${result.summary.bySeverity.high}\n- Medium: ${result.summary.bySeverity.medium}\n- Low: ${result.summary.bySeverity.low}\n- Info: ${result.summary.bySeverity.info}\n\n## Engines\n| Engine | Version | Status | Duration (ms) | Notes |\n|---|---|---|---:|---|\n${engineRows || '| mergesafe (mergesafe) | builtin | ok | 0 | - |'}\n\n## Top Findings\n${top || '- None'}\n`;
}

export function generateHtmlReport(result: ScanResult): string {
  const engineRows = (result.meta.engines ?? [])
    .map((entry) => {
      const artifacts = [
        entry.artifacts?.json ? `<a href="${escapeHtml(entry.artifacts.json)}">json</a>` : '',
        entry.artifacts?.sarif ? `<a href="${escapeHtml(entry.artifacts.sarif)}">sarif</a>` : '',
      ]
        .filter(Boolean)
        .join(' ');

      return `<tr><td>${escapeHtml(entry.displayName)}<br><code>${escapeHtml(entry.engineId)}</code></td><td>${escapeHtml(entry.version)}</td><td>${escapeHtml(entry.status)}</td><td>${entry.durationMs}</td><td>${escapeHtml(entry.errorMessage ?? entry.installHint ?? '-')}</td><td>${artifacts || '-'}</td></tr>`;
    })
    .join('');

  const rows = result.findings
    .map((f, i) => {
      const badges = [...new Set(f.engineSources.map((source) => source.engineId))]
        .map((engineId) => `<span class="engine-badge">${escapeHtml(engineId)}</span>`)
        .join(' ');
      const engineDetail = f.engineSources
        .map((source) => `<li><strong>${escapeHtml(source.engineId)}</strong> severity=${escapeHtml(source.engineSeverity ?? '-')} message=${escapeHtml(source.message ?? '-')}</li>`)
        .join('');
      return `<tr><td>${i + 1}</td><td>${escapeHtml(f.severity)}</td><td>${escapeHtml(f.title)}<div>${badges}</div></td><td>${escapeHtml(f.locations[0]?.filePath ?? '-')}:${f.locations[0]?.line ?? '-'}</td><td><details><summary>Details</summary><p>${escapeHtml(f.remediation)}</p><pre>${escapeHtml(f.evidence.excerpt ?? f.evidence.excerptHash ?? '')}</pre><p>Engine matrix:</p><ul>${engineDetail}</ul></details></td></tr>`;
    })
    .join('');

  return `<!doctype html><html><head><meta charset="utf-8"><title>MergeSafe Report</title><style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px;text-align:left}.badge{padding:4px 8px;border-radius:4px;background:#222;color:#fff}.engine-badge{display:inline-block;padding:2px 6px;margin:2px;border-radius:10px;background:#eef;color:#113;font-size:12px}</style></head><body><h1>MergeSafe Report</h1><p><span class="badge">${result.summary.status}</span> Grade ${result.summary.grade} / Score ${result.summary.score}</p><h2>Engines</h2><table><thead><tr><th>Engine</th><th>Version</th><th>Status</th><th>Duration (ms)</th><th>Error/Hint</th><th>Artifacts</th></tr></thead><tbody>${engineRows}</tbody></table><h2>Findings</h2><table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Location</th><th>Remediation</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}
