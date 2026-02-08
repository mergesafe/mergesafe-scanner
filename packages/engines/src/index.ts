import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  findingFingerprint,
  mergeCanonicalFindings,
  stableHash,
  type CliConfig,
  type Confidence,
  type EngineExecutionMeta,
  type Finding,
  type Severity,
} from '@mergesafe/core';
import { runDeterministicRules } from '@mergesafe/rules';

const execFileAsync = promisify(execFile);

export interface EngineContext {
  scanPath: string;
  config: CliConfig;
}

export interface EngineAdapter {
  engineId: string;
  displayName: string;
  installHint: string;
  version(): Promise<string>;
  isAvailable(ctx: EngineContext): Promise<boolean>;
  run(ctx: EngineContext): Promise<Finding[]>;
}

function normalizeSeverity(input: string, fallback: Severity = 'medium'): Severity {
  const key = input.toLowerCase();
  if (key === 'error' || key === 'critical') return 'critical';
  if (key === 'warning' || key === 'high') return 'high';
  if (key === 'medium') return 'medium';
  if (key === 'low') return 'low';
  if (key === 'info' || key === 'note') return 'info';
  return fallback;
}

/**
 * Cross-platform binary check (Windows + Linux + macOS)
 * Avoids `bash -lc` which breaks on Windows.
 */
async function hasBinary(name: string): Promise<boolean> {
  const envPath = process.env.PATH ?? '';
  const dirs = envPath.split(path.delimiter).filter(Boolean);

  const exts =
    process.platform === 'win32'
      ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM')
          .split(';')
          .map((e) => e.toLowerCase())
      : [''];

  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = process.platform === 'win32' ? path.join(dir, `${name}${ext}`) : path.join(dir, name);
      try {
        const stat = fs.statSync(candidate);
        if (stat.isFile()) return true;
      } catch {
        // continue
      }
    }
  }

  return false;
}

function withTimeout<T>(promise: Promise<T>, timeoutSec: number, timeoutError: Error): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(timeoutError), Math.max(timeoutSec, 1) * 1000);
    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

function canonicalFinding(args: {
  engineId: string;
  engineRuleId?: string;
  engineSeverity?: string;
  message: string;
  title: string;
  filePath: string;
  line: number;
  evidence: string; // can be '' when redacted
  confidence?: Confidence;
  category?: string;
  remediation?: string;
}): Finding {
  // Avoid collisions when evidence is redacted/empty
  const evidenceMaterial = args.evidence?.trim() ? args.evidence : `${args.engineId}:${args.engineRuleId ?? ''}:${args.message}`;
  const fingerprint = findingFingerprint(args.filePath, args.line, evidenceMaterial);
  const severity = normalizeSeverity(args.engineSeverity ?? 'medium');
  const excerptHash = stableHash(evidenceMaterial);

  return {
    findingId: `${args.engineId}-${args.engineRuleId ?? 'rule'}-${fingerprint}`,
    title: args.title,
    severity,
    confidence: args.confidence ?? 'medium',
    category: args.category ?? 'mcp-security',
    owaspMcpTop10: 'MCP-A10',
    engineSources: [
      {
        engineId: args.engineId,
        engineRuleId: args.engineRuleId,
        engineSeverity: args.engineSeverity,
        message: args.message,
      },
    ],
    locations: [{ filePath: args.filePath, line: args.line }],
    evidence: args.evidence?.trim()
      ? { excerpt: args.evidence, note: 'Engine finding evidence' }
      : { excerptHash, note: 'Evidence hash only (redacted or unavailable)' },
    remediation: args.remediation ?? 'Review and remediate based on engine guidance.',
    references: [],
    tags: [args.engineId],
    fingerprint,
  };
}

export class MergeSafeAdapter implements EngineAdapter {
  engineId = 'mergesafe';
  displayName = 'MergeSafe deterministic rules';
  installHint = 'Built in - no install required.';

  async version(): Promise<string> {
    return 'builtin';
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    const { findings: raw } = runDeterministicRules(ctx.scanPath, ctx.config.mode);
    return raw.map((entry) =>
      canonicalFinding({
        engineId: this.engineId,
        engineRuleId: entry.ruleId,
        engineSeverity: entry.severity,
        message: entry.title,
        title: entry.title,
        filePath: entry.filePath,
        line: entry.line,
        evidence: ctx.config.redact ? '' : entry.evidence,
        confidence: entry.confidence,
        category: entry.category,
        remediation: entry.remediation,
      })
    );
  }
}

export class SemgrepAdapter implements EngineAdapter {
  engineId = 'semgrep';
  displayName = 'Semgrep (local rules only)';
  installHint = 'Install semgrep locally (pip install semgrep) or enable it in GitHub Action.';

  async version(): Promise<string> {
    try {
      const { stdout } = await execFileAsync('semgrep', ['--version']);
      return stdout.trim() || 'unknown';
    } catch {
      return 'unavailable';
    }
  }

  async isAvailable(): Promise<boolean> {
    return hasBinary('semgrep');
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    // Windows-safe path resolution
    const here = path.dirname(fileURLToPath(import.meta.url));
    const rulesDir = path.resolve(here, '../semgrep-rules');

    const { stdout } = await execFileAsync(
      'semgrep',
      ['--config', rulesDir, '--json', '--metrics=off', ctx.scanPath],
      { maxBuffer: 20 * 1024 * 1024 }
    );

    const parsed = JSON.parse(stdout) as { results?: Array<Record<string, any>> };

    return (parsed.results ?? []).map((item) => {
      const extra = (item.extra ?? {}) as Record<string, any>;
      const start = (item.start ?? {}) as Record<string, any>;

      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: String(item.check_id ?? 'semgrep.rule'),
        engineSeverity: String(extra.severity ?? 'INFO'),
        message: String(extra.message ?? item.path ?? 'Semgrep finding'),
        title: String(extra.message ?? 'Semgrep finding'),
        filePath: path.resolve(ctx.scanPath, String(item.path ?? 'unknown')),
        line: Number(start.line ?? 1),
        evidence: ctx.config.redact ? '' : String((extra.lines ?? '').toString().trim()),
        confidence: 'medium',
      });
    });
  }
}

export class GitleaksAdapter implements EngineAdapter {
  engineId = 'gitleaks';
  displayName = 'Gitleaks';
  installHint = 'Install gitleaks locally (choco install gitleaks / scoop install gitleaks) or enable it in GitHub Action.';

  async version(): Promise<string> {
    try {
      const { stdout } = await execFileAsync('gitleaks', ['version']);
      return stdout.trim() || 'unknown';
    } catch {
      return 'unavailable';
    }
  }

  async isAvailable(): Promise<boolean> {
    return hasBinary('gitleaks');
  }

  async run(ctx: EngineContext): Promise<Finding[]> {
    const reportPath = path.join(os.tmpdir(), `mergesafe-gitleaks-${Date.now()}.json`);
    try {
      await execFileAsync(
        'gitleaks',
        ['detect', '--source', ctx.scanPath, '--report-format', 'json', '--report-path', reportPath, '--redact'],
        { maxBuffer: 10 * 1024 * 1024 }
      );
    } catch {
      // gitleaks returns non-zero when findings exist; continue parsing report.
    }

    if (!fs.existsSync(reportPath)) return [];
    const parsed = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as Array<Record<string, any>>;

    return parsed.map((item) => {
      const file = String(item.File ?? item.file ?? 'unknown');
      const line = Number(item.StartLine ?? item.startLine ?? 1);
      const rule = String(item.RuleID ?? item.rule ?? 'gitleaks.secret');
      const description = String(item.Description ?? item.description ?? 'Potential secret detected');

      // Never include raw secrets; keep it hashed even when not redacting overall.
      const fingerprintMaterial = [item.Fingerprint, item.Commit, item.Author].filter(Boolean).join(':') || description;

      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: rule,
        engineSeverity: 'high',
        message: description,
        title: description,
        filePath: path.resolve(ctx.scanPath, file),
        line,
        evidence: ctx.config.redact ? '' : stableHash(String(fingerprintMaterial)),
        confidence: 'high',
        category: 'secrets',
        remediation: 'Rotate exposed credentials and remove secrets from source history.',
      });
    });
  }
}

export const defaultAdapters: EngineAdapter[] = [new MergeSafeAdapter(), new SemgrepAdapter(), new GitleaksAdapter()];

export async function listEngines(ctx: EngineContext, adapters: EngineAdapter[] = defaultAdapters) {
  return Promise.all(
    adapters.map(async (adapter) => ({
      engineId: adapter.engineId,
      displayName: adapter.displayName,
      available: await adapter.isAvailable(ctx),
      version: await adapter.version(),
      installHint: adapter.installHint,
    }))
  );
}

export async function runEngines(
  ctx: EngineContext,
  selectedEngines: string[],
  adapters: EngineAdapter[] = defaultAdapters
): Promise<{ findings: Finding[]; meta: EngineExecutionMeta[] }> {
  const selected = adapters.filter((adapter) => selectedEngines.includes(adapter.engineId));
  const findings: Finding[] = [];
  const meta: EngineExecutionMeta[] = [];
  const queue = [...selected];
  const limit = Math.max(1, ctx.config.concurrency);

  const workers = new Array(Math.min(limit, queue.length)).fill(0).map(async () => {
    while (queue.length > 0) {
      const adapter = queue.shift();
      if (!adapter) break;

      const start = Date.now();
      const version = await adapter.version();
      const available = await adapter.isAvailable(ctx);

      if (!available) {
        meta.push({
          engineId: adapter.engineId,
          version,
          status: 'skipped',
          durationMs: Date.now() - start,
          installHint: adapter.installHint,
          errorMessage: `Not installed. ${adapter.installHint}`,
        });
        continue;
      }

      try {
        const result = await withTimeout(adapter.run(ctx), ctx.config.timeout, new Error(`Timed out after ${ctx.config.timeout}s`));
        findings.push(...result);
        meta.push({ engineId: adapter.engineId, version, status: 'ok', durationMs: Date.now() - start });
      } catch (error) {
        const err = error as Error;
        const timeout = /timed out/i.test(err.message);
        meta.push({
          engineId: adapter.engineId,
          version,
          status: timeout ? 'timeout' : 'failed',
          durationMs: Date.now() - start,
          errorMessage: err.message,
        });
      }
    }
  });

  await Promise.all(workers);

  return {
    findings: mergeCanonicalFindings(findings),
    meta: meta.sort((a, b) => selectedEngines.indexOf(a.engineId) - selectedEngines.indexOf(b.engineId)),
  };
}
