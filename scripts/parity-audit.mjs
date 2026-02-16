#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const writeMode = process.argv.includes('--write');

const OUTPUT_JSON = path.join(repoRoot, 'docs', 'parity', 'source-of-truth.json');
const OUTPUT_MD = path.join(repoRoot, 'docs', 'parity', 'source-of-truth.md');

const DEFAULT_KEYS = [
  'out-dir',
  'format',
  'mode',
  'timeout',
  'concurrency',
  'fail-on',
  'fail-on-scan-status',
  'auto-install',
  'path-mode',
  'verify-downloads',
  'max-file-bytes',
];

const ACTION_INPUT_KEYS = [
  'engines',
  'mode',
  'out-dir',
  'format',
  'fail-on',
  'fail-on-scan-status',
  'auto-install',
  'no-auto-install',
  'verify-downloads',
  'path-mode',
];

const CLAIM_KEYWORDS = [
  'offline',
  'airgapped',
  'air-gapped',
  'no internet',
  'no network',
  'offline-first',
  'default engines',
  'auto-install',
  'standard',
  'fast',
  'fail-on',
  'verify-downloads',
];

function run(cmd, args, options = {}) {
  const res = spawnSync(cmd, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: options.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });
  if (res.status !== 0) {
    if (options.capture) {
      process.stderr.write(res.stderr || '');
      process.stdout.write(res.stdout || '');
    }
    throw new Error(`Command failed: ${cmd} ${args.join(' ')}`);
  }
  return (res.stdout ?? '').replace(/\r\n/g, '\n');
}

function extractDefault(scanHelp, optionName) {
  const escaped = optionName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`--${escaped}\\b[^\\n]*\\(default:\\s*([^\\)]+)\\)`);
  const m = scanHelp.match(re);
  return m ? m[1].trim() : null;
}

function stripQuotes(raw) {
  const value = raw.trim();
  if (
    (value.startsWith("'") && value.endsWith("'")) ||
    (value.startsWith('"') && value.endsWith('"'))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function parseActionDefaults(actionPath) {
  const src = fs.readFileSync(actionPath, 'utf8').replace(/\r\n/g, '\n');
  const lines = src.split('\n');
  let inInputs = false;
  let currentInput = null;
  const defaults = {};

  for (const line of lines) {
    if (!inInputs) {
      if (/^inputs:\s*$/.test(line)) {
        inInputs = true;
      }
      continue;
    }

    if (/^runs:\s*$/.test(line) || /^outputs:\s*$/.test(line)) {
      break;
    }

    const inputMatch = line.match(/^\s{2}([a-zA-Z0-9_-]+):\s*$/);
    if (inputMatch) {
      currentInput = inputMatch[1].replace(/_/g, '-');
      continue;
    }

    if (!currentInput) continue;

    const defaultMatch = line.match(/^\s{4}default:\s*(.*)\s*$/);
    if (defaultMatch) {
      defaults[currentInput] = stripQuotes(defaultMatch[1]);
      currentInput = null;
    }
  }

  const picked = {};
  for (const key of ACTION_INPUT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(defaults, key)) {
      picked[key] = defaults[key];
    }
  }
  return picked;
}

function walkFiles(startPath, out = []) {
  const stat = fs.statSync(startPath);
  if (stat.isFile()) {
    out.push(startPath);
    return out;
  }
  for (const entry of fs.readdirSync(startPath, { withFileTypes: true })) {
    const full = path.join(startPath, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function scanClaims(files, keywords) {
  const lowerKeywords = keywords.map((k) => k.toLowerCase());
  const hits = [];

  for (const file of files) {
    const relPath = path.relative(repoRoot, file).split(path.sep).join('/');
    const src = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
    const lines = src.split('\n');

    lines.forEach((line, idx) => {
      const lower = line.toLowerCase();
      const matched = lowerKeywords.filter((kw) => lower.includes(kw));
      if (matched.length > 0) {
        hits.push({
          path: relPath,
          line: idx + 1,
          text: line.trim(),
          matched: matched.sort(),
        });
      }
    });
  }

  hits.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.text.localeCompare(b.text));
  return hits;
}

function buildPotentialMismatches(claimHits, cliDefaults) {
  const mismatches = [];
  const offlineTerms = ['offline', 'airgapped', 'air-gapped', 'no internet', 'no network', 'offline-first'];
  const hasOfflineClaim = claimHits.some((h) => offlineTerms.some((t) => h.text.toLowerCase().includes(t)));
  if (hasOfflineClaim && cliDefaults['auto-install'] === 'true') {
    mismatches.push({
      type: 'offline-claim-vs-auto-install-default',
      note: 'Offline/air-gapped claims found while CLI default for --auto-install is true (may download missing tools).',
    });
  }

  const fastDefaultClaim = claimHits.some(
    (h) => /default/i.test(h.text) && /\bfast\b/i.test(h.text)
  );
  if (fastDefaultClaim && cliDefaults.mode !== 'fast') {
    mismatches.push({
      type: 'fast-default-claim',
      note: `A claim suggests fast is default, but CLI help reports mode default as ${cliDefaults.mode}.`,
    });
  }

  const singleEngineClaim = claimHits.some((h) => {
    const t = h.text.toLowerCase();
    return /default/.test(t) && /engine/.test(t) && /(single|only|just|one)\s+engine/.test(t);
  });
  if (singleEngineClaim && Array.isArray(cliDefaults['default-engines']) && cliDefaults['default-engines'].length > 1) {
    mismatches.push({
      type: 'single-engine-default-claim',
      note: 'A claim suggests a single default engine, but DEFAULT_ENGINES contains multiple engines.',
    });
  }

  return mismatches;
}

function renderMarkdown(data) {
  const lines = [];
  lines.push('# MergeSafe parity audit: source of truth');
  lines.push('');
  lines.push('This file is generated by `scripts/parity-audit.mjs`.');
  lines.push('');

  lines.push('## Captured CLI help: `mergesafe --help`');
  lines.push('');
  lines.push('```text');
  lines.push(data.cliHelp.general.trimEnd());
  lines.push('```');
  lines.push('');

  lines.push('## Captured CLI help: `mergesafe scan --help`');
  lines.push('');
  lines.push('```text');
  lines.push(data.cliHelp.scan.trimEnd());
  lines.push('```');
  lines.push('');

  lines.push('## Defaults (from CLI help)');
  lines.push('');
  lines.push('| Option | Default |');
  lines.push('| --- | --- |');
  for (const key of DEFAULT_KEYS) {
    lines.push(`| ${key} | ${String(data.cliDefaults[key] ?? '')} |`);
  }
  lines.push('');

  lines.push('## Engine constants (from built core)');
  lines.push('');
  lines.push(`- DEFAULT_ENGINES: ${data.engineConstants.DEFAULT_ENGINES.join(', ')}`);
  lines.push(`- AVAILABLE_ENGINES: ${data.engineConstants.AVAILABLE_ENGINES.join(', ')}`);
  lines.push('');

  lines.push('## Action.yml defaults');
  lines.push('');
  lines.push('| Input | Default |');
  lines.push('| --- | --- |');
  for (const key of ACTION_INPUT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(data.actionDefaults, key)) {
      lines.push(`| ${key} | ${data.actionDefaults[key]} |`);
    }
  }
  lines.push('');

  lines.push('## Docs claim hits');
  lines.push('');
  for (const hit of data.docsClaimHits) {
    lines.push(`- ${hit.path}:${hit.line} — ${hit.text}`);
  }
  if (data.docsClaimHits.length === 0) {
    lines.push('- (none)');
  }
  lines.push('');

  lines.push('## Potential mismatches (heuristic)');
  lines.push('');
  if (data.potentialMismatches.length === 0) {
    lines.push('- (none)');
  } else {
    for (const mismatch of data.potentialMismatches) {
      lines.push(`- ${mismatch.type}: ${mismatch.note}`);
    }
  }
  lines.push('');

  return `${lines.join('\n')}\n`;
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function verifyOrWrite(targetPath, content) {
  if (writeMode) {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, content, 'utf8');
    return;
  }

  if (!fs.existsSync(targetPath)) {
    throw new Error(`Missing artifact: ${path.relative(repoRoot, targetPath)}. Run pnpm parity:update`);
  }

  const existing = fs.readFileSync(targetPath, 'utf8').replace(/\r\n/g, '\n');
  if (existing !== content) {
    throw new Error(`Artifact out of date: ${path.relative(repoRoot, targetPath)}. Run pnpm parity:update`);
  }
}

async function main() {
  run('pnpm', ['-r', 'build']);

  const cliEntry = path.join(repoRoot, 'packages', 'cli', 'dist', 'index.js');
  const cliHelpGeneral = run('node', [cliEntry, '--help'], { capture: true });
  const cliHelpScan = run('node', [cliEntry, 'scan', '--help'], { capture: true });

  const cliDefaults = {};
  for (const key of DEFAULT_KEYS) {
    cliDefaults[key] = extractDefault(cliHelpScan, key);
  }

  const coreDist = path.join(repoRoot, 'packages', 'core', 'dist', 'index.js');
  const coreMod = await import(pathToFileURL(coreDist).href);
  const defaultEngines = [...(coreMod.DEFAULT_ENGINES ?? [])];
  const availableEngines = [...(coreMod.AVAILABLE_ENGINES ?? [])];
  cliDefaults['default-engines'] = [...defaultEngines];

  const actionPath = path.join(repoRoot, 'packages', 'action', 'action.yml');
  const actionDefaults = parseActionDefaults(actionPath);

  const ignoredDocFiles = new Set([
    OUTPUT_JSON,
    OUTPUT_MD,
  ]);

  const docFiles = [
    path.join(repoRoot, 'README.md'),
    ...walkFiles(path.join(repoRoot, 'docs')).filter((file) => {
      if (file.includes(`${path.sep}_local${path.sep}`)) return false;
      return !ignoredDocFiles.has(file);
    }),
    actionPath,
  ].sort((a, b) => a.localeCompare(b));
  const docsClaimHits = scanClaims(docFiles, CLAIM_KEYWORDS);

  const payload = {
    cliHelp: {
      general: cliHelpGeneral.trimEnd(),
      scan: cliHelpScan.trimEnd(),
    },
    cliDefaults,
    engineConstants: {
      DEFAULT_ENGINES: defaultEngines,
      AVAILABLE_ENGINES: availableEngines,
    },
    actionDefaults,
    docsClaimHits,
  };

  payload.potentialMismatches = buildPotentialMismatches(payload.docsClaimHits, payload.cliDefaults);

  const jsonOut = stableJson(payload);
  const mdOut = renderMarkdown(payload);

  verifyOrWrite(OUTPUT_JSON, jsonOut);
  verifyOrWrite(OUTPUT_MD, mdOut);

  process.stdout.write(
    `${writeMode ? 'Wrote' : 'Verified'} parity artifacts:\n- docs/parity/source-of-truth.json\n- docs/parity/source-of-truth.md\n`
  );
}

main().catch((err) => {
  process.stderr.write(`${err?.message || String(err)}\n`);
  process.exit(1);
});
