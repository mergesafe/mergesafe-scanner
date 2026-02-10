import fs from 'node:fs';
import path from 'node:path';
import type { RawFinding } from '@mergesafe/core';

interface FileInfo { filePath: string; content: string; lines: string[] }

export interface ToolSurface {
  name: string;
  hints: string[];
  capabilities: string[];
  filePath: string;
}

const FILE_EXTS = ['.ts','.js','.py','.json','.yml','.yaml'];

function collectFiles(targetPath: string): FileInfo[] {
  const out: FileInfo[] = [];
  const walk = (p: string) => {
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      for (const child of fs.readdirSync(p)) walk(path.join(p, child));
      return;
    }
    if (!FILE_EXTS.includes(path.extname(p))) return;
    const content = fs.readFileSync(p, 'utf8');
    out.push({ filePath: p, content, lines: content.split(/\r?\n/) });
  };
  walk(targetPath);
  return out;
}

function lineOf(content: string, pattern: RegExp): number {
  const idx = content.search(pattern);
  if (idx < 0) return 1;
  return content.slice(0, idx).split(/\r?\n/).length;
}

function firstLineMatch(content: string, pattern: RegExp): string {
  const m = content.match(pattern);
  if (!m) return '';
  // If the regex is multiline line-capture-ish, m[0] is usually enough.
  return String(m[0] ?? '').trim();
}

function mk(
  ruleId:string,
  title:string,
  severity:RawFinding['severity'],
  file:FileInfo,
  pattern:RegExp,
  evidence:string,
  remediation:string,
  tags:string[],
  category='mcp-security',
  owasp='MCP-A05'
): RawFinding {
  return {
    ruleId,
    title,
    severity,
    confidence:'medium',
    category,
    owaspMcpTop10: owasp,
    filePath:file.filePath,
    line: lineOf(file.content, pattern),
    evidence,
    remediation,
    references:['https://owasp.org'],
    tags
  };
}

/* ------------------------- heuristics helpers ------------------------- */

function hasHttpHandlerContext(c: string): boolean {
  return (
    /http\.createServer\s*\(/i.test(c) ||
    /\bcreateServer\s*\(/i.test(c) ||
    /\bserver\.listen\s*\(/i.test(c) ||
    /\bapp\.(get|post|put|delete|patch|use)\s*\(/i.test(c) ||
    /\brouter\.(get|post|put|delete|patch|use)\s*\(/i.test(c) ||
    /\b(req|request)\b\s*,\s*\b(res|response)\b/i.test(c)
  );
}

function hasUserInputSource(c: string): boolean {
  return (
    /url\.parse\s*\(\s*req\.url/i.test(c) ||
    /\bnew\s+URL\s*\(\s*req\.url/i.test(c) ||
    /\breq\.(query|body|params|headers)\b/i.test(c) ||
    /\bprocess\.argv\b/i.test(c) ||
    /\bargv\b/i.test(c)
  );
}

// Command-exec sinks (Node + Python)
const EXEC_SINK_RE =
  /\b(execSync|exec|spawnSync|spawn|fork)\s*\(|\bchild_process\b|\bsubprocess\.Popen\b/i;

// High-confidence “user-controlled arg hits sink” (simple, line-ish)
const EXEC_TAINT_CALL_RE =
  /\b(execSync|exec|spawnSync|spawn|fork)\s*\(\s*(q|query|params|body|req|request)\b/i;

// FS write sinks
const FS_WRITE_SINK_RE =
  /\bfs\.writeFileSync\b|\bfs\.writeFile\b|\bfs\.appendFile\b|\bcreateWriteStream\b|\bopen\s*\(.*\bw\b/i;

// Common “user-ish” inputs
const GENERIC_USER_INPUT_RE =
  /\b(req\.|request\.|input\b|body\b|argv\b|params\b|query\b)\b/i;

export function extractToolSurface(files: FileInfo[]): ToolSurface[] {
  const tools: ToolSurface[] = [];
  for (const file of files) {
    const nameMatch = file.content.match(/tool\s*[:=]\s*['\"]([\w.-]+)['\"]|registerTool\(['\"]([\w.-]+)['\"]/g) || [];
    for (const raw of nameMatch) {
      const name = raw.match(/['\"]([\w.-]+)['\"]/)?.[1] ?? 'unknown';
      const hints: string[] = [];
      if (/readOnlyHint|readonly/i.test(file.content)) hints.push('readOnlyHint');
      if (/destructiveHint/i.test(file.content)) hints.push('destructiveHint');
      if (/idempotentHint/i.test(file.content)) hints.push('idempotentHint');
      const capabilities = [
        /exec\(|child_process|subprocess/.test(file.content) ? 'exec' : '',
        /readFile|open\(|Path\(/.test(file.content) ? 'fs-read' : '',
        /writeFile|appendFile|open\(.+w/.test(file.content) ? 'fs-write' : '',
        /fetch\(|axios|requests\./.test(file.content) ? 'net-egress' : '',
        /token|secret|apikey/i.test(file.content) ? 'secrets' : '',
        /auth|middleware|jwt/i.test(file.content) ? 'auth' : '',
      ].filter(Boolean);
      tools.push({ name, hints, capabilities, filePath: file.filePath });
    }
  }
  return tools;
}

export function runDeterministicRules(
  targetPath: string,
  mode: 'fast'|'deep'='fast'
): { findings: RawFinding[]; tools: ToolSurface[] } {
  const files = collectFiles(targetPath);
  const tools = extractToolSurface(files);
  const findings: RawFinding[] = [];

  for (const file of files) {
    const c = file.content;

    // MS001
    if (/destructive|delete|drop\s+table|rm\s+-rf/i.test(c) && !/auth|gate|confirm|allowlist/i.test(c)) {
      findings.push(mk(
        'MS001',
        'Destructive tools exposed without gating hints',
        'high',
        file,
        /destructive|delete|rm\s+-rf/i,
        firstLineMatch(c, /.*(delete|rm\s+-rf|drop\s+table).*/i) || 'destructive pattern',
        'Require explicit authorization/gating hints.',
        ['destructive','gating'],
        'tooling',
        'MCP-A01'
      ));
    }

    // ✅ MS002 (UPDATED): command execution + request/user-input context
    // Previously required "tool|handler|endpoint|route" which misses plain http servers.
    if (EXEC_SINK_RE.test(c)) {
      const httpCtx = hasHttpHandlerContext(c);
      const userInput = hasUserInputSource(c);

      // High-confidence: sink call looks like it takes req/q/query/params/body directly
      const taintCall = EXEC_TAINT_CALL_RE.test(c);

      // Medium-confidence: sink exists AND file is clearly request-handling AND has user input sources
      if (taintCall || (httpCtx && userInput)) {
        findings.push(mk(
          'MS002',
          'Command execution reachable from request/user input',
          'critical',
          file,
          /\b(execSync|exec|spawnSync|spawn|fork)\s*\(|subprocess\.Popen/i,
          firstLineMatch(c, /.*\b(execSync|exec|spawnSync|spawn|fork)\s*\(.*$/im) || 'Potential command execution in request flow',
          'Avoid shell execution; sanitize inputs and isolate commands. Prefer allowlists and safe APIs.',
          ['exec'],
          'injection',
          'MCP-A03'
        ));
      }
    }

    // MS003 (filesystem write + user-ish inputs)
    // Slightly tightened sink regex; still relies on cheap heuristics.
    if (FS_WRITE_SINK_RE.test(c) && GENERIC_USER_INPUT_RE.test(c)) {
      findings.push(mk(
        'MS003',
        'Filesystem write with user-controlled paths',
        'high',
        file,
        /\b(fs\.writeFileSync|fs\.writeFile|fs\.appendFile|createWriteStream|open\s*\(.*\bw\b)/i,
        firstLineMatch(c, /.*\b(fs\.writeFileSync|fs\.writeFile|fs\.appendFile|createWriteStream)\b.*$/im) || 'User-controlled file write path detected',
        'Use path normalization and allowlisted directories. Never write to arbitrary paths from requests.',
        ['fs-write','path-traversal'],
        'filesystem',
        'MCP-A04'
      ));
    }

    // MS004
    if (/(fetch\(|axios\.|requests\.|http\.request)/.test(c) && /tool|handler|route|endpoint/i.test(c) && !/allowlist|ALLOWED_HOSTS/.test(c)) {
      findings.push(mk(
        'MS004',
        'Network egress from tool handlers without allowlist',
        'high',
        file,
        /fetch\(|axios\.|requests\.|http\.request/,
        'Outgoing network call in handler without allowlist',
        'Enforce explicit egress allowlist.',
        ['net-egress'],
        'network',
        'MCP-A06'
      ));
    }

    // MS005
    if (/(console\.log|print)\(.*(token|secret|api[_-]?key|password)/i.test(c)) {
      findings.push(mk(
        'MS005',
        'Secrets or tokens likely logged or dumped',
        'high',
        file,
        /(console\.log|print)\(/,
        'Sensitive value appears in logs',
        'Redact secrets before logging.',
        ['secrets'],
        'secrets',
        'MCP-A02'
      ));
    }

    // MS006
    if (/(scope[s]?\s*[:=].*(\*|admin|full_access|all))/i.test(c)) {
      findings.push(mk(
        'MS006',
        'Overly-broad OAuth scope patterns in config',
        'medium',
        file,
        /scope[s]?\s*[:=]/,
        'Broad OAuth scope detected',
        'Use least-privilege OAuth scopes.',
        ['oauth'],
        'authz',
        'MCP-A07'
      ));
    }

    // MS007
    if (/(app\.(get|post|use)|@app\.route|FastAPI\()/i.test(c) && /mcp|tool/i.test(c) && !/(auth|jwt|apikey|middleware)/i.test(c)) {
      findings.push(mk(
        'MS007',
        'Missing auth middleware smell on HTTP MCP endpoints',
        'high',
        file,
        /(app\.(get|post)|@app\.route|FastAPI\()/,
        'Endpoint appears unauthenticated',
        'Add auth middleware to MCP endpoints.',
        ['auth'],
        'authn',
        'MCP-A01'
      ));
    }

    // MS008
    if (/(debug\s*=\s*true|ALLOW_ALL\s*=\s*true|CORS\(\{\s*origin:\s*['\"]\*['\"])/i.test(c)) {
      findings.push(mk(
        'MS008',
        'Unsafe defaults (debug/allow-all)',
        'medium',
        file,
        /debug\s*=\s*true|ALLOW_ALL\s*=\s*true|origin:\s*['\"]\*['\"]/,
        'Unsafe permissive defaults found',
        'Disable debug and tighten allow-lists.',
        ['defaults'],
        'hardening',
        'MCP-A08'
      ));
    }

    // MS009
    if (/read[-_ ]?only/i.test(c) && /(writeFile|fetch\(|requests\.|exec\()/i.test(c)) {
      findings.push(mk(
        'MS009',
        'Tool descriptions claim read-only but code suggests writes/egress',
        'medium',
        file,
        /read[-_ ]?only/i,
        'Read-only claim conflicts with mutating capabilities',
        'Align tool metadata with actual capabilities.',
        ['tool-metadata'],
        'integrity',
        'MCP-A09'
      ));
    }

    // MS010
    if (/(registerTool|tools\[.+\]|eval\().*(req\.|input|body|argv|json)/i.test(c)) {
      findings.push(mk(
        'MS010',
        'Dynamic tool registration from untrusted input',
        'critical',
        file,
        /registerTool|tools\[.+\]|eval\(/,
        'Dynamic tool registration from user input detected',
        'Disallow dynamic tool registration from untrusted data.',
        ['dynamic-tools'],
        'integrity',
        'MCP-A10'
      ));
    }

    // MS011 (deep)
    if (mode === 'deep' && /(eval\(|Function\(|exec\(req\.|subprocess\.Popen\(request)/.test(c)) {
      findings.push(mk(
        'MS011',
        'Deep mode: dynamic code execution sink',
        'critical',
        file,
        /eval\(|Function\(/,
        'Dynamic code execution in request flow',
        'Remove dynamic execution primitives.',
        ['exec','deep'],
        'injection',
        'MCP-A03'
      ));
    }
  }

  return { findings, tools };
}
