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

function mk(ruleId:string,title:string,severity:RawFinding['severity'],file:FileInfo,pattern:RegExp,evidence:string,remediation:string,tags:string[],category='mcp-security',owasp='MCP-A05'): RawFinding {
  return {
    ruleId, title, severity, confidence:'medium', category, owaspMcpTop10: owasp,
    filePath:file.filePath, line: lineOf(file.content, pattern), evidence, remediation, references:['https://owasp.org'], tags
  };
}

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

export function runDeterministicRules(targetPath: string, mode: 'fast'|'deep'='fast'): { findings: RawFinding[]; tools: ToolSurface[] } {
  const files = collectFiles(targetPath);
  const tools = extractToolSurface(files);
  const findings: RawFinding[] = [];

  for (const file of files) {
    const c = file.content;
    if (/destructive|delete|drop\s+table|rm\s+-rf/i.test(c) && !/auth|gate|confirm|allowlist/i.test(c)) {
      findings.push(mk('MS001','Destructive tools exposed without gating hints','high',file,/destructive|delete|rm\s+-rf/i,c.match(/.*(delete|rm -rf).*/i)?.[0] ?? 'destructive pattern','Require explicit authorization/gating hints.',['destructive','gating'],'tooling','MCP-A01'));
    }
    if (/exec\(|spawn\(|child_process|subprocess\.Popen/.test(c) && /tool|handler|endpoint|route/i.test(c)) {
      findings.push(mk('MS002','Command execution reachable from tool handlers','critical',file,/exec\(|spawn\(|subprocess\.Popen/, 'Potential command execution in handler','Avoid shell execution; sanitize inputs and isolate commands.',['exec'],'injection','MCP-A03'));
    }
    if (/(writeFile|open\(.+w|Path\(.+\+|fs\.writeFileSync)/.test(c) && /(req\.|input|body|argv|params)/.test(c)) {
      findings.push(mk('MS003','Filesystem write with user-controlled paths','high',file,/writeFile|fs\.writeFileSync|open\(.+w/,'User-controlled file write path detected','Use path normalization and allowlisted directories.',['fs-write','path-traversal'],'filesystem','MCP-A04'));
    }
    if (/(fetch\(|axios\.|requests\.|http\.request)/.test(c) && /tool|handler|route|endpoint/i.test(c) && !/allowlist|ALLOWED_HOSTS/.test(c)) {
      findings.push(mk('MS004','Network egress from tool handlers without allowlist','high',file,/fetch\(|axios\.|requests\.|http\.request/,'Outgoing network call in handler without allowlist','Enforce explicit egress allowlist.',['net-egress'],'network','MCP-A06'));
    }
    if (/(console\.log|print)\(.*(token|secret|api[_-]?key|password)/i.test(c)) {
      findings.push(mk('MS005','Secrets or tokens likely logged or dumped','high',file,/(console\.log|print)\(/,'Sensitive value appears in logs','Redact secrets before logging.',['secrets'],'secrets','MCP-A02'));
    }
    if (/(scope[s]?\s*[:=].*(\*|admin|full_access|all))/i.test(c)) {
      findings.push(mk('MS006','Overly-broad OAuth scope patterns in config','medium',file,/scope[s]?\s*[:=]/,'Broad OAuth scope detected','Use least-privilege OAuth scopes.',['oauth'],'authz','MCP-A07'));
    }
    if (/(app\.(get|post|use)|@app\.route|FastAPI\()/i.test(c) && /mcp|tool/i.test(c) && !/(auth|jwt|apikey|middleware)/i.test(c)) {
      findings.push(mk('MS007','Missing auth middleware smell on HTTP MCP endpoints','high',file,/(app\.(get|post)|@app\.route|FastAPI\()/,'Endpoint appears unauthenticated','Add auth middleware to MCP endpoints.',['auth'],'authn','MCP-A01'));
    }
    if (/(debug\s*=\s*true|ALLOW_ALL\s*=\s*true|CORS\(\{\s*origin:\s*['\"]\*['\"])/i.test(c)) {
      findings.push(mk('MS008','Unsafe defaults (debug/allow-all)','medium',file,/debug\s*=\s*true|ALLOW_ALL\s*=\s*true|origin:\s*['\"]\*['\"]/,'Unsafe permissive defaults found','Disable debug and tighten allow-lists.',['defaults'],'hardening','MCP-A08'));
    }
    if (/read[-_ ]?only/i.test(c) && /(writeFile|fetch\(|requests\.|exec\()/i.test(c)) {
      findings.push(mk('MS009','Tool descriptions claim read-only but code suggests writes/egress','medium',file,/read[-_ ]?only/i,'Read-only claim conflicts with mutating capabilities','Align tool metadata with actual capabilities.',['tool-metadata'],'integrity','MCP-A09'));
    }
    if (/(registerTool|tools\[.+\]|eval\().*(req\.|input|body|argv|json)/i.test(c)) {
      findings.push(mk('MS010','Dynamic tool registration from untrusted input','critical',file,/registerTool|tools\[.+\]|eval\(/,'Dynamic tool registration from user input detected','Disallow dynamic tool registration from untrusted data.',['dynamic-tools'],'integrity','MCP-A10'));
    }
    if (mode === 'deep' && /(eval\(|Function\(|exec\(req\.|subprocess\.Popen\(request)/.test(c)) {
      findings.push(mk('MS011','Deep mode: dynamic code execution sink','critical',file,/eval\(|Function\(/,'Dynamic code execution in request flow','Remove dynamic execution primitives.',['exec','deep'],'injection','MCP-A03'));
    }
  }

  return { findings, tools };
}
