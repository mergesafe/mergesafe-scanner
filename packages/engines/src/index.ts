import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
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

function canonicalFinding(args: {
  engineId: string;
  engineRuleId?: string;
  engineSeverity?: string;
  message: string;
  title: string;
  filePath: string;
  line: number;
  evidence: string;
  confidence?: Confidence;
  category?: string;
  remediation?: string;
}): Finding {
  const fingerprint = findingFingerprint(args.filePath, args.line, args.evidence);
  const severity = normalizeSeverity(args.engineSeverity ?? 'medium');
  const excerptHash = stableHash(args.evidence);
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
    evidence: args.evidence ? { excerpt: args.evidence, note: 'Engine finding evidence' } : { excerptHash, note: 'Evidence hash only' },
    remediation: args.remediation ?? 'Review and remediate based on engine guidance.',
    references: [],
    tags: [args.engineId],
    fingerprint,
  };
}

async function hasBinary(name: string): Promise<boolean> {
  try {
    await execFileAsync('bash', ['-lc', `command -v ${name}`]);
    return true;
  } catch {
    return false;
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutSec: number, timeoutError: Error): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(timeoutError), Math.max(timeoutSec, 1) * 1000);
    promise.then((result) => {
      clearTimeout(timer);
      resolve(result);
    }).catch((err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
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
    return raw.map((entry) => canonicalFinding({
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
    }));
  }
}

export class SemgrepAdapter implements EngineAdapter {
  engineId = 'semgrep';
  displayName = 'Semgrep (local rules only)';
  installHint = 'Install semgrep locally (https://semgrep.dev/docs/getting-started/).';

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
    const rulesDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../semgrep-rules');
    const { stdout } = await execFileAsync('semgrep', ['--config', rulesDir, '--json', '--metrics=off', ctx.scanPath], { maxBuffer: 20 * 1024 * 1024 });
    const parsed = JSON.parse(stdout) as { results?: Array<Record<string, unknown>> };
    return (parsed.results ?? []).map((item) => {
      const extra = (item.extra ?? {}) as Record<string, unknown>;
      const start = ((item.start ?? {}) as Record<string, unknown>);
      return canonicalFinding({
        engineId: this.engineId,
        engineRuleId: String(item.check_id ?? 'semgrep.rule'),
        engineSeverity: String(extra.severity ?? 'INFO'),
        message: String(extra.message ?? item.path ?? 'Semgrep finding'),
        title: String(extra.message ?? 'Semgrep finding'),
        filePath: path.resolve(ctx.scanPath, String(item.path ?? 'unknown')),
        line: Number(start.line ?? 1),
        evidence: String((extra.lines ?? '').toString().trim()),
        confidence: 'medium',
      });
    });
  }
}

export class GitleaksAdapter implements EngineAdapter {
  engineId = 'gitleaks';
  displayName = 'Gitleaks';
  installHint = 'Install gitleaks locally (https://github.com/gitleaks/gitleaks).';

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
      await execFileAsync('gitleaks', ['detect', '--source', ctx.scanPath, '--report-format', 'json', '--report-path', reportPath, '--redact'], { maxBuffer: 10 * 1024 * 1024 });
    } catch {
      // gitleaks returns non-zero when findings exist; continue parsing report.
    }
    if (!fs.existsSync(reportPath)) return [];
    const parsed = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as Array<Record<string, unknown>>;
    return parsed.map((item) => {
      const file = String(item.File ?? item.file ?? 'unknown');
      const line = Number(item.StartLine ?? item.startLine ?? 1);
      const rule = String(item.RuleID ?? item.rule ?? 'gitleaks.secret');
      const description = String(item.Description ?? item.description ?? 'Potential secret detected');
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
  return Promise.all(adapters.map(async (adapter) => ({
    engineId: adapter.engineId,
    displayName: adapter.displayName,
    available: await adapter.isAvailable(ctx),
    version: await adapter.version(),
    installHint: adapter.installHint,
  })));
}

export async function runEngines(ctx: EngineContext, selectedEngines: string[], adapters: EngineAdapter[] = defaultAdapters): Promise<{ findings: Finding[]; meta: EngineExecutionMeta[] }> {
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
        meta.push({ engineId: adapter.engineId, version, status: 'skipped', durationMs: Date.now() - start, installHint: adapter.installHint, errorMessage: `Not installed. ${adapter.installHint}` });
        continue;
      }
      try {
        const result = await withTimeout(adapter.run(ctx), ctx.config.timeout, new Error(`Timed out after ${ctx.config.timeout}s`));
        findings.push(...result);
        meta.push({ engineId: adapter.engineId, version, status: 'ok', durationMs: Date.now() - start });
      } catch (error) {
        const err = error as Error;
        const timeout = /timed out/i.test(err.message);
        meta.push({ engineId: adapter.engineId, version, status: timeout ? 'timeout' : 'failed', durationMs: Date.now() - start, errorMessage: err.message });
      }
    }
  });
  await Promise.all(workers);
  return { findings: mergeCanonicalFindings(findings), meta: meta.sort((a, b) => selectedEngines.indexOf(a.engineId) - selectedEngines.indexOf(b.engineId)) };
}
