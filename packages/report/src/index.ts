// packages/report/src/index.ts
import path from 'node:path';
import type { Finding, ScanResult } from '@mergesafe/core';

const severityRank: Record<Finding['severity'], number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const confidenceRank: Record<Finding['confidence'], number> = { high: 3, medium: 2, low: 1 };


type GateSummary = {
  status?: unknown;
  failOn?: unknown;
  reason?: unknown;
};

type ResultSummaryView = {
  status?: unknown;
  scanStatus?: unknown;
  gate?: GateSummary;
};

function readResultSummary(result: ScanResult): ResultSummaryView {
  const summary = result.summary as unknown;
  if (!summary || typeof summary !== 'object') return {};
  return summary as ResultSummaryView;
}

/**
 * PR4 determinism helpers (display-layer only)
 * - Always render with POSIX separators in MD/HTML
 * - Avoid machine-specific absolute paths leaking via engine notes/errors
 */
function toPosixPath(p: string): string {
  return String(p ?? '').replaceAll('\\', '/');
}

function scrubMachinePaths(text: string): string {
  let s = String(text ?? '');

  // Normalize separators first (so patterns are simpler)
  s = s.replaceAll('\\', '/');

  // Replace Windows absolute paths like C:/Users/... or D:/a/b/...
  // Keep it conservative: only replace when it clearly looks like a local path.
  s = s.replace(/\b[A-Za-z]:\/[^\s"')]+/g, '<path>');

  // Replace common Unix absolute paths like /home/runner/... /Users/... /tmp/...
  s = s.replace(/\b\/(home|Users|private|var|tmp|opt|etc)\/[^\s"')]+/g, '<path>');

  return s;
}

function escapeHtml(value: string): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * PR4: Do NOT resort findings in report layer.
 * Assume CLI already applied canonical stable ordering.
 */
function topFindings(result: ScanResult): Finding[] {
  return (result.findings ?? []).slice(0, 5);
}

function displayLocation(f: Finding): string {
  const loc = f.locations?.[0];
  if (!loc) return '-';
  const fp = toPosixPath(loc.filePath);
  const line = loc.line ?? '-';
  return `${fp}:${line}`;
}


function compactEvidence(f: Finding): string {
  const parts: string[] = [];
  if (f.evidence?.matchType) parts.push(`type=${String(f.evidence.matchType)}`);
  if (f.evidence?.ruleId) parts.push(`rule=${String(f.evidence.ruleId)}`);
  if (f.evidence?.matchSummary) parts.push(`summary=${scrubMachinePaths(String(f.evidence.matchSummary)).slice(0, 160)}`);
  if (f.evidence?.matchedSnippet) parts.push(`snippet=${scrubMachinePaths(String(f.evidence.matchedSnippet)).slice(0, 160)}`);

  if (!parts.length) {
    const fallback = scrubMachinePaths(String(f.evidence?.excerpt ?? f.evidence?.excerptHash ?? '')).slice(0, 160);
    return fallback || '-';
  }
  return parts.join('; ');
}

function artifactHref(artifactPath?: string): string | undefined {
  if (!artifactPath) return undefined;

  // Prefer a relative link rooted at the outDir (report.html lives in outDir).
  // We strip everything before "/artifacts/" so links work on Windows/macOS/Linux.
  const norm = toPosixPath(artifactPath);
  const idx = norm.lastIndexOf('/artifacts/');
  if (idx >= 0) return norm.slice(idx + 1); // "artifacts/..."
  // Already relative (best effort)
  if (!path.isAbsolute(artifactPath)) return norm;
  return undefined;
}

function engineNoteMarkdown(entry: NonNullable<ScanResult['meta']['engines']>[number]): string {
  const baseRaw = entry.errorMessage ?? entry.installHint ?? '-';
  const base = scrubMachinePaths(baseRaw);

  if (entry.engineId !== 'cisco') return base;

  // Cisco needs explicit clarification so users don't think it's scanning repo source by default.
  if (entry.status === 'ok') {
    const extra =
      'Cisco scanned MCP client config(s) from known locations on this machine (not repo source). Validate relevance to the project.';
    return base && base !== '-' ? `${extra} ${base}` : extra;
  }

  if (entry.status === 'skipped') {
    const extra =
      'Cisco skipped (offline-safe). To scan repo via Cisco static mode, provide tools JSON (e.g. --cisco-tools <path>) or run on a machine with MCP client configs.';
    return base && base !== '-' ? `${extra} ${base}` : extra;
  }

  return base;
}

function engineNoteHtml(entry: NonNullable<ScanResult['meta']['engines']>[number]): string {
  const baseRaw = entry.errorMessage ?? entry.installHint ?? '-';
  const base = scrubMachinePaths(baseRaw);

  if (entry.engineId !== 'cisco') return escapeHtml(base);

  if (entry.status === 'ok') {
    const extra =
      'Cisco scanned MCP client config(s) from known locations on this machine (not repo source). Validate relevance to the project.';
    return escapeHtml(base && base !== '-' ? `${extra} ${base}` : extra);
  }

  if (entry.status === 'skipped') {
    const extra =
      'Cisco skipped (offline-safe). To scan repo via Cisco static mode, provide tools JSON (e.g. --cisco-tools <path>) or run on a machine with MCP client configs.';
    return escapeHtml(base && base !== '-' ? `${extra} ${base}` : extra);
  }

  return escapeHtml(base);
}

function engineLabelMap(result: ScanResult): Record<string, string> {
  const engines = result.meta.engines ?? [];
  const map: Record<string, string> = {};
  for (const e of engines) map[e.engineId] = e.displayName;
  return map;
}

function uniqueEngineIds(f: Finding): string[] {
  return [...new Set((f.engineSources ?? []).map((s) => String(s.engineId ?? '').trim()).filter(Boolean))].sort((a, b) =>
    a.localeCompare(b)
  );
}

/**
 * Human labels for scan execution state.
 */
function formatScanStatus(status: string | undefined): string {
  const s = String(status ?? '').toUpperCase();
  if (s === 'OK') return 'OK';
  if (s === 'PARTIAL') return 'Partial';
  if (s === 'FAILED') return 'Failed';
  return status ? String(status) : 'OK';
}

/**
 * Extract "gate" object if present, else fall back.
 */
function gateStatusFromResult(result: ScanResult): { status?: string; failOn?: string; reason?: string } {
  const summary = readResultSummary(result);
  const gate = summary.gate;
  if (gate && typeof gate === 'object') {
    return {
      status: gate.status != null ? String(gate.status) : undefined,
      failOn: gate.failOn != null ? String(gate.failOn) : undefined,
      reason: gate.reason != null ? String(gate.reason) : undefined,
    };
  }

  // Back-compat: older summary.status might have been PASS/FAIL
  return { status: summary.status != null ? String(summary.status) : undefined };
}

/**
 * Convert PASS/FAIL + failOn into non-confusing text:
 * - failOn=none => DISABLED
 * - otherwise PASS => ALLOWED, FAIL => BLOCKED
 */
function formatPolicyGate(result: ScanResult): { label: string; detail?: string } {
  const gate = gateStatusFromResult(result);

  const failOn = String(gate.failOn ?? '').toLowerCase();
  const rawStatus = String(gate.status ?? '').toUpperCase(); // PASS/FAIL (today)
  const reason = gate.reason ? scrubMachinePaths(String(gate.reason)) : '';

  // If failOn is none, treat gate as disabled regardless of status
  if (failOn === 'none') {
    const detailParts: string[] = [];
    if (failOn) detailParts.push(`failOn=${failOn}`);
    if (reason) detailParts.push(reason);
    return { label: 'DISABLED', detail: detailParts.join('; ') || undefined };
  }

  if (rawStatus === 'FAIL') {
    const detailParts: string[] = [];
    if (failOn) detailParts.push(`failOn=${failOn}`);
    if (reason) detailParts.push(reason);
    return { label: 'BLOCKED', detail: detailParts.join('; ') || undefined };
  }

  // default to allowed (covers PASS/unknown)
  const detailParts: string[] = [];
  if (failOn) detailParts.push(`failOn=${failOn}`);
  if (reason) detailParts.push(reason);
  return { label: 'ALLOWED', detail: detailParts.join('; ') || undefined };
}

/**
 * Markdown header block (summary.md)
 */
function markdownStatusBlock(result: ScanResult): string {
  const summary = readResultSummary(result);
  const scanStatusRaw = String(summary.scanStatus ?? 'OK').toUpperCase();
  const scanStatus = formatScanStatus(scanStatusRaw);
  const gateRaw = String((summary.gate?.status ?? summary.status ?? 'PASS')).toUpperCase();
  const gateStatus = gateRaw === 'FAIL' ? 'FAIL' : 'PASS';
  const gate = formatPolicyGate(result);

  const gateLine = gate.detail ? `**${gate.label}** (${gate.detail})` : `**${gate.label}**`;
  const warning = scanStatusRaw !== 'OK' ? '\n> ⚠️ Partial scan: some engines failed or were skipped.' : '';

  return `Scan status: **${scanStatus}**\nGate status: **${gateStatus}**\nPolicy gate: ${gateLine}\nRisk grade: **${result.summary.grade}** (score ${result.summary.score})${warning}`;
}

/**
 * HTML header pills (report.html)
 */
function htmlHeaderBadges(result: ScanResult): string {
  const summary = readResultSummary(result);
  const scanStatusRaw = String(summary.scanStatus ?? 'OK').toUpperCase();
  const scanLabel = formatScanStatus(scanStatusRaw);
  const gateRaw = String((summary.gate?.status ?? summary.status ?? 'PASS')).toUpperCase();
  const gateStatus = gateRaw === 'FAIL' ? 'FAIL' : 'PASS';
  const gate = formatPolicyGate(result);
  const warning =
    scanStatusRaw !== 'OK'
      ? '<div class="warn">⚠️ Partial scan: some engines failed or were skipped.</div>'
      : '';

  return `
    <div class="meta">
      <div class="pill"><span class="k">Scan status</span> <span class="v">${escapeHtml(scanLabel)}</span></div>
      <div class="pill"><span class="k">Gate status</span> <span class="v">${escapeHtml(gateStatus)}</span></div>
      <div class="pill">
        <span class="k">Policy gate</span>
        <span class="v">${escapeHtml(gate.label)}</span>
        ${gate.detail ? `<div class="sub">${escapeHtml(gate.detail)}</div>` : ''}
      </div>
      <div class="pill"><span class="k">Risk grade</span> <span class="v">${escapeHtml(result.summary.grade)} / ${escapeHtml(
        String(result.summary.score)
      )}</span></div>
    </div>
    ${warning}
  `;
}

function sortedEngines(result: ScanResult): NonNullable<ScanResult['meta']['engines']> {
  const engines = result.meta.engines ?? [];
  // Deterministic ordering independent of runtime/concurrency.
  return engines.slice().sort((a, b) => {
    const id = String(a.engineId).localeCompare(String(b.engineId));
    if (id !== 0) return id;
    return String(a.displayName).localeCompare(String(b.displayName));
  });
}

export function generateSummaryMarkdown(result: ScanResult): string {
  const engines = sortedEngines(result);

  const engineRows = engines
    .map(
      (entry) =>
        `| ${entry.displayName} (${entry.engineId}) | ${entry.version} | ${entry.status} | ${entry.durationMs} | ${engineNoteMarkdown(
          entry
        )} |`
    )
    .join('\n');

  const label = engineLabelMap(result);

  const top = topFindings(result)
    .map((f) => {
      const ids = uniqueEngineIds(f);
      const attribution = ids.map((id) => label[id] ?? id).join(', ');
      const confirmed = ids.length > 1 ? ' ✅ Multi-engine confirmed' : '';
      const where = displayLocation(f);
      return `- **${String(f.severity).toUpperCase()}** ${f.title} (${where}) — Found by: ${attribution}${confirmed}\n  - Evidence: ${compactEvidence(f)}`;
    })
    .join('\n');

  const hasCisco = engines.some((e) => e.engineId === 'cisco');
  const cisco = engines.find((e) => e.engineId === 'cisco');

  const ciscoBlock =
    hasCisco && cisco
      ? `\n## Cisco note
Cisco is **offline-safe by default** in MergeSafe. When it runs via **known-configs**, it scans MCP client configs on the machine (Cursor/Windsurf/VS Code, etc.), which may be unrelated to the repo.

- If you want Cisco to scan the repo deterministically: use **static tools JSON** (e.g. \`--cisco-tools tools-list.json\`).
- If Cisco shows **skipped**, that is expected when no configs/tools are available.\n`
      : '';

  return `# MergeSafe Summary

${markdownStatusBlock(result)}

## Totals
- Total findings: ${result.summary.totalFindings}
- Critical: ${result.summary.bySeverity.critical}
- High: ${result.summary.bySeverity.high}
- Medium: ${result.summary.bySeverity.medium}
- Low: ${result.summary.bySeverity.low}
- Info: ${result.summary.bySeverity.info}

## Engines
| Engine | Version | Status | Duration (ms) | Notes |
|---|---|---|---:|---|
${engineRows || '| mergesafe (mergesafe) | builtin | ok | 0 | - |'}

${ciscoBlock}
## Top Findings
${top || '- None'}
`;
}

export function generateHtmlReport(result: ScanResult): string {
  const engines = sortedEngines(result);
  const label = engineLabelMap(result);

  const engineRows = engines
    .map((entry) => {
      const jsonHref = artifactHref(entry.artifacts?.json);
      const sarifHref = artifactHref(entry.artifacts?.sarif);

      const artifacts = [
        jsonHref ? `<a href="${escapeHtml(jsonHref)}">json</a>` : '',
        sarifHref ? `<a href="${escapeHtml(sarifHref)}">sarif</a>` : '',
      ]
        .filter(Boolean)
        .join(' ');

      const note = engineNoteHtml(entry);

      return `<tr>
        <td>${escapeHtml(entry.displayName)}<br><code>${escapeHtml(entry.engineId)}</code></td>
        <td>${escapeHtml(entry.version)}</td>
        <td>${escapeHtml(entry.status)}</td>
        <td>${entry.durationMs}</td>
        <td>${note}</td>
        <td>${artifacts || '-'}</td>
      </tr>`;
    })
    .join('');

  // PR4: preserve input order (assumed stable) — do not resort.
  const rows = (result.findings ?? [])
    .map((f, i) => {
      const ids = uniqueEngineIds(f);
      const names = ids.map((id) => label[id] ?? id);
      const foundByText = names.join(', ');
      const multiEngine = ids.length > 1;

      const badges = ids.map((engineId) => `<span class="engine-badge">${escapeHtml(engineId)}</span>`).join(' ');

      const foundBy = `<div class="found-by">
        <span class="found-by-label">Found by:</span> ${escapeHtml(foundByText)}
        ${multiEngine ? `<span class="confirm-badge">Multi-engine confirmed</span>` : ''}
      </div>`;

      const engineDetail = (f.engineSources ?? [])
        .slice()
        .sort((a: NonNullable<Finding['engineSources']>[number], b: NonNullable<Finding['engineSources']>[number]) => {
          const e = String(a.engineId).localeCompare(String(b.engineId));
          if (e !== 0) return e;
          const r = String(a.engineRuleId ?? '').localeCompare(String(b.engineRuleId ?? ''));
          if (r !== 0) return r;
          const s = String(a.engineSeverity ?? '').localeCompare(String(b.engineSeverity ?? ''));
          if (s !== 0) return s;
          return String(a.message ?? '').localeCompare(String(b.message ?? ''));
        })
        .map(
          (source) =>
            `<li><strong>${escapeHtml(label[source.engineId] ?? source.engineId)}</strong> (<code>${escapeHtml(
              source.engineId
            )}</code>) severity=${escapeHtml(source.engineSeverity ?? '-')} message=${escapeHtml(source.message ?? '-')}</li>`
        )
        .join('');

      const loc = f.locations?.[0];
      const where = loc ? `${escapeHtml(toPosixPath(loc.filePath))}:${loc.line ?? '-'}` : '-';

      const evidenceText = scrubMachinePaths(f.evidence?.excerpt ?? f.evidence?.excerptHash ?? "");
      const evidenceCompact = compactEvidence(f);

      return `<tr>
        <td>${i + 1}</td>
        <td>${escapeHtml(f.severity)}</td>
        <td>
          ${escapeHtml(f.title)}
          <div class="badges">${badges}</div>
          ${foundBy}
        </td>
        <td>${where}</td>
        <td>
          <details>
            <summary>Details</summary>
            <p>${escapeHtml(f.remediation)}</p>
            <pre>${escapeHtml(evidenceText)}</pre>
            <p><strong>Evidence:</strong> ${escapeHtml(evidenceCompact)}</p>
            <p>Engine matrix:</p>
            <ul>${engineDetail || '<li>-</li>'}</ul>
          </details>
        </td>
      </tr>`;
    })
    .join('');

  const hasCisco = engines.some((e) => e.engineId === 'cisco');

  const ciscoNoteHtml = hasCisco
    ? `<div class="callout">
        <strong>Cisco note:</strong> Cisco runs <em>offline-safe</em> by default. When it runs via <code>known-configs</code>,
        it scans MCP client configs on this machine (Cursor/Windsurf/VS Code, etc.), which may be unrelated to the repo.
        To scan the repo deterministically with Cisco, use static tools JSON (e.g. <code>--cisco-tools tools-list.json</code>).
      </div>`
    : '';

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>MergeSafe Report</title>
  <style>
    body{font-family:Arial,sans-serif;margin:20px}
    table{border-collapse:collapse;width:100%}
    td,th{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}
    .badge{padding:4px 8px;border-radius:4px;background:#222;color:#fff}
    .engine-badge{display:inline-block;padding:2px 6px;margin:2px;border-radius:10px;background:#eef;color:#113;font-size:12px}
    .badges{margin-top:4px}
    .found-by{margin-top:6px;font-size:12px;color:#333}
    .found-by-label{font-weight:700}
    .confirm-badge{display:inline-block;margin-left:8px;padding:2px 6px;border-radius:10px;background:#e8fff0;color:#0a5d2a;border:1px solid #b9f2cf;font-weight:700}
    .callout{margin:12px 0;padding:10px 12px;border:1px solid #cfd8ff;background:#f6f8ff;border-radius:8px}
    code{background:#f4f4f4;padding:2px 4px;border-radius:4px}
    pre{white-space:pre-wrap;word-break:break-word;background:#f7f7f7;padding:8px;border-radius:6px;border:1px solid #ddd}

    /* Header pills */
    .meta{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 14px}
    .pill{border:1px solid #ddd;border-radius:12px;padding:10px 12px;background:#fafafa;min-width:220px}
    .pill .k{display:block;font-size:12px;color:#555;font-weight:700;margin-bottom:4px}
    .pill .v{display:block;font-size:16px;font-weight:800}
    .pill .sub{margin-top:6px;font-size:12px;color:#333}
    .warn{margin:8px 0 12px;padding:10px 12px;border:1px solid #f0c36d;background:#fff8e6;border-radius:8px;color:#7a4b00;font-weight:700}
  </style>
</head>
<body>
  <h1>MergeSafe Report</h1>

  ${htmlHeaderBadges(result)}

  ${ciscoNoteHtml}

  <h2>Engines</h2>
  <table>
    <thead>
      <tr>
        <th>Engine</th>
        <th>Version</th>
        <th>Status</th>
        <th>Duration (ms)</th>
        <th>Error/Hint</th>
        <th>Artifacts</th>
      </tr>
    </thead>
    <tbody>${engineRows || ''}</tbody>
  </table>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Title</th>
        <th>Location</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}
