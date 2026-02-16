// packages/rules/src/index.ts
import fs from "node:fs";
import path from "node:path";
import type { RawFinding } from "@mergesafe/core";
import { scanJsTaint } from "./js_taint.js";
import { emitToolsManifestFindings, type ToolSurface } from "./tools_manifest.js";

/* ------------------------- debug helpers (env-gated) ------------------------- */

const DEBUG_FINGERPRINT =
  process.env.MERGESAFE_DEBUG === "1" ||
  String(process.env.DEBUG || "").toLowerCase().includes("mergesafe");

const DEBUG_LIMIT = (() => {
  const n = Number.parseInt(String(process.env.MERGESAFE_DEBUG_LIMIT ?? "200"), 10);
  return Number.isFinite(n) && n > 0 ? n : 200;
})();

function dbg(event: string, payload?: Record<string, unknown>) {
  if (!DEBUG_FINGERPRINT) return;
  // Keep logs grep-friendly in GH Actions
  const msg = payload ? `${event} ${JSON.stringify(payload)}` : event;
  console.error(`[mergesafe:rules] ${msg}`);
}

function safeRealpath(p: string): string {
  try {
    const native = (fs.realpathSync as unknown as { native?: (p: string) => string }).native;
    return native ? native(p) : fs.realpathSync(p);
  } catch {
    return p;
  }
}

interface FileInfo {
  // Stable, repo-relative (POSIX) path used in findings/output keys
  filePath: string;
  // Absolute path used for filesystem reads/stats
  absPath: string;
  content: string;
  lines: string[];
  sizeBytes: number;
}

export type DeterministicSkipReason = "ignored" | "symlink" | "too_large" | "unsupported_ext" | "read_error";

export interface DeterministicScanStats {
  filesConsidered: number;
  filesScanned: number;
  filesSkipped: number;
  skipReasons: Record<DeterministicSkipReason, number>;
}

interface CollectOptions {
  maxFileBytes: number;
}

const FILE_EXTS = [
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".json",
  ".yml",
  ".yaml",
];

const JS_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

/**
 * Directory ignore policy (performance + noise).
 * Keep this conservative: skip the obvious huge / generated folders.
 */
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;

const IGNORE_DIR_NAMES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  "mergesafe",
  ".next",
  "coverage",
  ".cache",
  ".turbo",
  ".pnpm",
  ".yarn",
  ".npm",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".idea",
]);

/**
 * Tools manifest filenames we treat as policy inputs.
 * We SKIP these in the generic heuristic scan loop to avoid noisy false positives.
 * (The manifest is handled by emitToolsManifestFindings as the single source of truth.)
 */
const TOOLS_MANIFEST_BASENAMES = new Set([
  "tools-list.json",
  "tool-list.json",
  "tools.json",
  "mcp-tools.json",
  "mcp.tools.json",
  "tools.manifest.json",
]);

/**
 * Deterministic comparator (avoid locale/ICU differences across OS)
 */
function asciiCompare(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function stableCompare(a: unknown, b: unknown): number {
  return asciiCompare(String(a ?? ""), String(b ?? ""));
}

function toPosix(p: string): string {
  return String(p ?? "").replace(/\\/g, "/");
}

function isToolsManifestFile(stablePosixPath: string): boolean {
  // stablePosixPath is already POSIX; use path.posix to avoid platform quirks
  const base = path.posix.basename(toPosix(stablePosixPath)).toLowerCase();
  return TOOLS_MANIFEST_BASENAMES.has(base);
}

function shouldSkipDir(dirPath: string): boolean {
  const base = path.basename(dirPath).toLowerCase();
  if (IGNORE_DIR_NAMES.has(base)) return true;

  if (base.startsWith(".") && base !== "." && base !== "..") {
    if (base === ".github" || base === ".vscode") return false;
    return true;
  }

  return false;
}

function shouldIgnoreFile(absPath: string): boolean {
  const base = path.basename(absPath).toLowerCase();
  return base === ".ds_store" || base === "thumbs.db";
}

function initStats(): DeterministicScanStats {
  return {
    filesConsidered: 0,
    filesScanned: 0,
    filesSkipped: 0,
    skipReasons: {
      ignored: 0,
      symlink: 0,
      too_large: 0,
      unsupported_ext: 0,
      read_error: 0,
    },
  };
}

function recordSkip(stats: DeterministicScanStats, reason: DeterministicSkipReason): void {
  stats.filesSkipped += 1;
  stats.skipReasons[reason] += 1;
}

function readTextSafe(p: string): string {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
}

/**
 * Normalize any file path (absolute or relative) into a stable
 * repo-relative POSIX path based on targetAbs.
 *
 * IMPORTANT: This stabilizes fingerprints across OS/CI runners.
 */
function normalizeFindingFilePath(filePath: string, targetAbs: string): string {
  const raw = String(filePath ?? "");
  if (!raw) return "unknown";

  const targetRoot = safeRealpath(path.resolve(targetAbs));
  const abs = path.isAbsolute(raw) ? path.resolve(raw) : path.resolve(targetRoot, raw);

  // Prefer a stable relative path.
  let rel = path.relative(targetRoot, abs);

  // Avoid empty rel (can happen if filePath == targetAbs)
  if (!rel) rel = path.basename(abs);

  // Strip leading "./" if present and normalize separators
  rel = rel.replace(/^[.][\\/]/, "");

  return toPosix(rel);
}

function collectFiles(targetAbsInput: string, options: CollectOptions): { files: FileInfo[]; stats: DeterministicScanStats } {
  const out: FileInfo[] = [];
  const targetAbs = safeRealpath(path.resolve(targetAbsInput));
  const stats = initStats();

  const walk = (absPath: string) => {
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(absPath);
    } catch {
      recordSkip(stats, "read_error");
      return;
    }

    if (lst.isSymbolicLink()) {
      recordSkip(stats, "symlink");
      return;
    }

    if (lst.isDirectory()) {
      if (shouldSkipDir(absPath)) {
        recordSkip(stats, "ignored");
        return;
      }

      let children: string[] = [];
      try {
        children = fs.readdirSync(absPath);
      } catch {
        recordSkip(stats, "read_error");
        return;
      }

      children.sort(asciiCompare);

      for (const child of children) {
        walk(path.join(absPath, child));
      }
      return;
    }

    if (!lst.isFile()) return;

    stats.filesConsidered += 1;

    if (shouldIgnoreFile(absPath)) {
      recordSkip(stats, "ignored");
      return;
    }

    const ext = path.extname(absPath).toLowerCase();
    if (!FILE_EXTS.includes(ext)) {
      recordSkip(stats, "unsupported_ext");
      return;
    }

    if (lst.size > options.maxFileBytes) {
      recordSkip(stats, "too_large");
      return;
    }

    const content = readTextSafe(absPath);
    if (!content && lst.size > 0) {
      recordSkip(stats, "read_error");
      return;
    }

    let rel = path.relative(targetAbs, absPath);
    if (!rel) rel = path.basename(absPath);
    rel = rel.replace(/^[.][\\/]/, "");

    out.push({
      filePath: toPosix(rel),
      absPath,
      content,
      lines: content.split(/\r?\n/),
      sizeBytes: lst.size,
    });
    stats.filesScanned += 1;
  };

  walk(targetAbs);

  out.sort((a, b) => stableCompare(a.filePath, b.filePath));

  const skipReasons = Object.fromEntries(
    Object.entries(stats.skipReasons).sort(([a], [b]) => asciiCompare(a, b))
  ) as DeterministicScanStats["skipReasons"];

  return {
    files: out,
    stats: { ...stats, skipReasons },
  };
}

function lineOf(content: string, pattern: RegExp): number {
  const idx = content.search(pattern);
  if (idx < 0) return 1;
  return content.slice(0, idx).split(/\r?\n/).length;
}

function firstLineMatch(content: string, pattern: RegExp): string {
  const m = content.match(pattern);
  if (!m) return "";
  return String(m[0] ?? "").trim();
}

function mk(
  ruleId: string,
  title: string,
  severity: RawFinding["severity"],
  file: FileInfo,
  pattern: RegExp,
  evidence: string,
  remediation: string,
  tags: string[],
  category = "mcp-security",
  owasp = "MCP-A05",
  matchType: "regex" | "heuristic" = "regex"
): RawFinding {
  const findingLine = lineOf(file.content, pattern);
  return {
    ruleId,
    title,
    severity,
    confidence: "medium",
    category,
    owaspMcpTop10: owasp,
    filePath: file.filePath,
    line: findingLine,
    evidence,
    evidencePayload: {
      ruleId,
      matchType,
      matchedSnippet: evidence.slice(0, 160),
      locations: [{ filePath: file.filePath, line: findingLine }],
    },
    remediation,
    references: ["https://owasp.org"],
    tags,
  };
}

function mkLoc(
  ruleId: string,
  title: string,
  severity: RawFinding["severity"],
  file: FileInfo,
  line: number,
  evidence: string,
  remediation: string,
  tags: string[],
  category = "mcp-security",
  owasp = "MCP-A05",
  matchSummary?: string
): RawFinding {
  const findingLine = Math.max(1, line || 1);
  return {
    ruleId,
    title,
    severity,
    confidence: "medium",
    category,
    owaspMcpTop10: owasp,
    filePath: file.filePath,
    line: findingLine,
    evidence,
    evidencePayload: {
      ruleId,
      matchType: "taint",
      matchedSnippet: evidence.slice(0, 160),
      ...(matchSummary ? { matchSummary } : {}),
      locations: [{ filePath: file.filePath, line: findingLine }],
    },
    remediation,
    references: ["https://owasp.org"],
    tags,
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

const EXEC_SINK_RE =
  /\b(execSync|exec|spawnSync|spawn|fork)\s*\(|\bchild_process\b|\bsubprocess\.Popen\b/i;

const EXEC_TAINT_CALL_RE =
  /\b(execSync|exec|spawnSync|spawn|fork)\s*\(\s*(q|query|params|body|req|request)\b/i;

const FS_WRITE_SINK_RE =
  /\bfs\.writeFileSync\b|\bfs\.writeFile\b|\bfs\.appendFile\b|\bcreateWriteStream\b|\bopen\s*\(.*\bw\b/i;

const GENERIC_USER_INPUT_RE =
  /\b(req\.|request\.|input\b|body\b|argv\b|params\b|query\b)\b/i;

/* ------------------------- existing code tool surface ------------------------- */

export function extractToolSurface(files: FileInfo[]): ToolSurface[] {
  const tools: ToolSurface[] = [];
  for (const file of files) {
    const nameMatch =
      file.content.match(/tool\s*[:=]\s*['"]([\w.-]+)['"]|registerTool\(['"]([\w.-]+)['"]/g) || [];
    for (const raw of nameMatch) {
      const name = raw.match(/['"]([\w.-]+)['"]/)?.[1] ?? "unknown";
      const hints: string[] = [];
      if (/readOnlyHint|readonly/i.test(file.content)) hints.push("readOnlyHint");
      if (/destructiveHint/i.test(file.content)) hints.push("destructiveHint");
      if (/idempotentHint/i.test(file.content)) hints.push("idempotentHint");
      const capabilities = [
        /exec\(|child_process|subprocess/.test(file.content) ? "exec" : "",
        /readFile|open\(|Path\(/.test(file.content) ? "fs-read" : "",
        /writeFile|appendFile|open\(.+w/.test(file.content) ? "fs-write" : "",
        /fetch\(|axios|requests\./.test(file.content) ? "net-egress" : "",
        /token|secret|apikey/i.test(file.content) ? "secrets" : "",
        /auth|middleware|jwt/i.test(file.content) ? "auth" : "",
      ].filter(Boolean);
      tools.push({ name, hints, capabilities, filePath: file.filePath });
    }
  }
  return tools;
}

function dedupeKeyForFinding(f: RawFinding): string {
  // NOTE: manifest findings often land on line=1. Including evidence/tags reduces accidental collapsing.
  const ev = (f.evidence ?? "").trim().slice(0, 160);

  // ✅ make tag component stable even if tag order differs
  const tagList = Array.isArray((f as any).tags) ? ((f as any).tags as string[]) : [];
  const tags = [...new Set(tagList.map((t) => String(t ?? "").trim()).filter(Boolean))].sort(asciiCompare).join(",");

  return `${f.ruleId}|${f.filePath}|${f.line}|${f.title}|${ev}|${tags}`;
}

export function runDeterministicRules(
  targetPath: string,
  mode: "fast" | "deep" = "fast",
  options?: { maxFileBytes?: number }
 ): { findings: RawFinding[]; tools: ToolSurface[]; scanStats: DeterministicScanStats } {
  const targetAbs = safeRealpath(path.resolve(targetPath));
  const maxFileBytes = Math.max(1, Number(options?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES));

  if (DEBUG_FINGERPRINT) {
    dbg("start", {
      platform: process.platform,
      node: process.version,
      cwd: process.cwd(),
      targetPath,
      targetAbs,
      mode,
      maxFileBytes,
    });
  }

  const { files, stats: scanStats } = collectFiles(targetAbs, { maxFileBytes });

  if (DEBUG_FINGERPRINT) {
    dbg("files", {
      count: files.length,
      sample: files.slice(0, Math.min(10, files.length)).map((f) => f.filePath),
    });
  }

  const findings: RawFinding[] = [];
  const dedupe = new Set<string>();

  let debugCount = 0;

  const pushFinding = (f: RawFinding) => {
    // Normalize ANY incoming finding path (including tools manifest findings)
    const normalized: RawFinding = {
      ...f,
      filePath: normalizeFindingFilePath(f.filePath, targetAbs),
      line: Math.max(1, Number(f.line || 1)),
      ...(f.evidencePayload
        ? {
            evidencePayload: {
              ...f.evidencePayload,
              ruleId: f.ruleId,
              ...(f.evidencePayload.locations
                ? {
                    locations: f.evidencePayload.locations.map((loc) => ({
                      ...loc,
                      filePath: normalizeFindingFilePath(loc.filePath, targetAbs),
                      line: Math.max(1, Number(loc.line || 1)),
                    })),
                  }
                : {}),
            },
          }
        : {}),
    };

    const key = dedupeKeyForFinding(normalized);
    if (dedupe.has(key)) return;
    dedupe.add(key);
    findings.push(normalized);

    if (DEBUG_FINGERPRINT && debugCount < DEBUG_LIMIT) {
      debugCount++;
      dbg("finding", {
        n: debugCount,
        ruleId: normalized.ruleId,
        filePath: normalized.filePath,
        line: normalized.line,
        title: normalized.title,
      });
    }
  };

  // 1) Tools manifest policy checks (single source of truth)
  const manifestToolsRaw = emitToolsManifestFindings(targetAbs, pushFinding);

  // ✅ Also normalize tool-surface file paths coming from the manifest emitter
  const manifestTools: ToolSurface[] = (manifestToolsRaw ?? []).map((t) => ({
    ...t,
    filePath: normalizeFindingFilePath((t as any).filePath ?? "unknown", targetAbs),
  }));

  // 2) Existing code-surface tool extraction (already stable because files[] uses stable file.filePath)
  const codeTools = extractToolSurface(files);

  // Merge tool surfaces (manifest + code), dedupe by filePath+name
  const toolSeen = new Set<string>();
  const tools: ToolSurface[] = [];
  for (const t of [...manifestTools, ...codeTools]) {
    const key = `${t.filePath}|${t.name}`;
    if (toolSeen.has(key)) continue;
    toolSeen.add(key);
    tools.push(t);
  }

  for (const file of files) {
    // Skip manifest files in the generic heuristic scan loop to avoid noise/false positives.
    if (isToolsManifestFile(file.filePath)) continue;

    const c = file.content;
    const ext = path.posix.extname(toPosix(file.filePath)).toLowerCase();
    const isJs = JS_EXTS.has(ext);

    // MS001
    if (
      /destructive|delete|drop\s+table|rm\s+-rf/i.test(c) &&
      !/auth|gate|confirm|allowlist/i.test(c)
    ) {
      pushFinding(
        mk(
          "MS001",
          "Destructive tools exposed without gating hints",
          "high",
          file,
          /destructive|delete|rm\s+-rf/i,
          firstLineMatch(c, /.*(delete|rm\s+-rf|drop\s+table).*/i) || "destructive pattern",
          "Require explicit authorization/gating hints.",
          ["destructive", "gating"],
          "tooling",
          "MCP-A01",
          "heuristic"
        )
      );
    }

    if (isJs) {
      const taintFindings = scanJsTaint(file.content, file.filePath);
      for (const tf of taintFindings) {
        if (tf.ruleId === "MS002") {
          const evidenceLine =
            file.lines[tf.line - 1]?.trim() || `${tf.sink}(... tainted arg #${tf.taintedArgIndex})`;
          pushFinding(
            mkLoc(
              "MS002",
              "Command execution from user-controlled input",
              "critical",
              file,
              tf.line,
              evidenceLine,
              "Avoid shell execution; never pass request-derived data into process execution. Prefer allowlists, safe APIs, and strict input validation.",
              ["exec", "taint"],
              "injection",
              "MCP-A03",
              `source=user_input -> sink=${tf.sink}`
            )
          );
        } else if (tf.ruleId === "MS003") {
          const evidenceLine =
            file.lines[tf.line - 1]?.trim() || `${tf.sink}(... tainted arg #${tf.taintedArgIndex})`;
          pushFinding(
            mkLoc(
              "MS003",
              "Filesystem write with user-controlled path",
              "high",
              file,
              tf.line,
              evidenceLine,
              "Use path normalization and allowlisted directories. Never write to arbitrary paths derived from requests or user input.",
              ["fs-write", "path-traversal", "taint"],
              "filesystem",
              "MCP-A04",
              `source=user_input -> sink=${tf.sink}`
            )
          );
        }
      }
    } else {
      if (EXEC_SINK_RE.test(c)) {
        const httpCtx = hasHttpHandlerContext(c);
        const userInput = hasUserInputSource(c);
        const taintCall = EXEC_TAINT_CALL_RE.test(c);

        if (taintCall || (httpCtx && userInput)) {
          pushFinding(
            mk(
              "MS002",
              "Command execution reachable from request/user input",
              "critical",
              file,
              /\b(execSync|exec|spawnSync|spawn|fork)\s*\(|subprocess\.Popen/i,
              firstLineMatch(c, /.*\b(execSync|exec|spawnSync|spawn|fork)\s*\(.*$/im) ||
                "Potential command execution in request flow",
              "Avoid shell execution; sanitize inputs and isolate commands. Prefer allowlists and safe APIs.",
              ["exec"],
              "injection",
              "MCP-A03"
            )
          );
        }
      }

      if (FS_WRITE_SINK_RE.test(c) && GENERIC_USER_INPUT_RE.test(c)) {
        pushFinding(
          mk(
            "MS003",
            "Filesystem write with user-controlled paths",
            "high",
            file,
            /\b(fs\.writeFileSync|fs\.writeFile|fs\.appendFile|createWriteStream|open\s*\(.*\bw\b)/i,
            firstLineMatch(
              c,
              /.*\b(fs\.writeFileSync|fs\.writeFile|fs\.appendFile|createWriteStream)\b.*$/im
            ) || "User-controlled file write path detected",
            "Use path normalization and allowlisted directories. Never write to arbitrary paths from requests.",
            ["fs-write", "path-traversal"],
            "filesystem",
            "MCP-A04",
            "heuristic"
          )
        );
      }
    }

    // MS004
    if (
      /(fetch\(|axios\.|requests\.|http\.request)/.test(c) &&
      /tool|handler|route|endpoint/i.test(c) &&
      !/allowlist|ALLOWED_HOSTS/.test(c)
    ) {
      pushFinding(
        mk(
          "MS004",
          "Network egress from tool handlers without allowlist",
          "high",
          file,
          /fetch\(|axios\.|requests\.|http\.request/,
          "Outgoing network call in handler without allowlist",
          "Enforce explicit egress allowlist.",
          ["net-egress"],
          "network",
          "MCP-A06",
          "heuristic"
        )
      );
    }

    // MS005
    if (/(console\.log|print)\(.*(token|secret|api[_-]?key|password)/i.test(c)) {
      pushFinding(
        mk(
          "MS005",
          "Secrets or tokens likely logged or dumped",
          "high",
          file,
          /(console\.log|print)\(/,
          "Sensitive value appears in logs",
          "Redact secrets before logging.",
          ["secrets"],
          "secrets",
          "MCP-A02",
          "heuristic"
        )
      );
    }

    // MS006
    if (/(scope[s]?\s*[:=].*(\*|admin|full_access|all))/i.test(c)) {
      pushFinding(
        mk(
          "MS006",
          "Overly-broad OAuth scope patterns in config",
          "medium",
          file,
          /scope[s]?\s*[:=]/,
          "Broad OAuth scope detected",
          "Use least-privilege OAuth scopes.",
          ["oauth"],
          "authz",
          "MCP-A07",
          "heuristic"
        )
      );
    }

    // MS007
    if (
      /(app\.(get|post|use)|@app\.route|FastAPI\()/i.test(c) &&
      /mcp|tool/i.test(c) &&
      !/(auth|jwt|apikey|middleware)/i.test(c)
    ) {
      pushFinding(
        mk(
          "MS007",
          "Missing auth middleware smell on HTTP MCP endpoints",
          "high",
          file,
          /(app\.(get|post)|@app\.route|FastAPI\()/,
          "Endpoint appears unauthenticated",
          "Add auth middleware to MCP endpoints.",
          ["auth"],
          "authn",
          "MCP-A01",
          "heuristic"
        )
      );
    }

    // MS008
    if (/(debug\s*=\s*true|ALLOW_ALL\s*=\s*true|CORS\(\{\s*origin:\s*['"]\*['"])/i.test(c)) {
      pushFinding(
        mk(
          "MS008",
          "Unsafe defaults (debug/allow-all)",
          "medium",
          file,
          /debug\s*=\s*true|ALLOW_ALL\s*=\s*true|origin:\s*['"]\*['"]/,
          "Unsafe permissive defaults found",
          "Disable debug and tighten allow-lists.",
          ["defaults"],
          "hardening",
          "MCP-A08",
          "heuristic"
        )
      );
    }

    // MS009
    if (/read[-_ ]?only/i.test(c) && /(writeFile|fetch\(|requests\.|exec\()/i.test(c)) {
      pushFinding(
        mk(
          "MS009",
          "Tool descriptions claim read-only but code suggests writes/egress",
          "medium",
          file,
          /read[-_ ]?only/i,
          "Read-only claim conflicts with mutating capabilities",
          "Align tool metadata with actual capabilities.",
          ["tool-metadata"],
          "integrity",
          "MCP-A09",
          "heuristic"
        )
      );
    }

    // MS010
    if (/(registerTool|tools\[.+\]|eval\().*(req\.|input|body|argv|json)/i.test(c)) {
      pushFinding(
        mk(
          "MS010",
          "Dynamic tool registration from untrusted input",
          "critical",
          file,
          /registerTool|tools\[.+\]|eval\(/,
          "Dynamic tool registration from user input detected",
          "Disallow dynamic tool registration from untrusted data.",
          ["dynamic-tools"],
          "integrity",
          "MCP-A10",
          "heuristic"
        )
      );
    }

    // MS011 (deep)
    if (mode === "deep" && /(eval\(|Function\(|exec\(req\.|subprocess\.Popen\(request)/.test(c)) {
      pushFinding(
        mk(
          "MS011",
          "Deep mode: dynamic code execution sink",
          "critical",
          file,
          /eval\(|Function\(/,
          "Dynamic code execution in request flow",
          "Remove dynamic execution primitives.",
          ["exec", "deep"],
          "injection",
          "MCP-A03",
          "heuristic"
        )
      );
    }
  }

  // ✅ Deterministic ordering for outputs/tests
  tools.sort((a, b) => {
    const p = stableCompare(a.filePath, b.filePath);
    if (p !== 0) return p;
    return stableCompare(a.name, b.name);
  });

  findings.sort((a, b) => {
    const p = stableCompare(a.filePath, b.filePath);
    if (p !== 0) return p;
    const l = Number(a.line ?? 0) - Number(b.line ?? 0);
    if (l !== 0) return l;
    const r = stableCompare(a.ruleId, b.ruleId);
    if (r !== 0) return r;
    const t = stableCompare(a.title, b.title);
    if (t !== 0) return t;
    return stableCompare(a.evidence ?? "", b.evidence ?? "");
  });

  if (DEBUG_FINGERPRINT) {
    dbg("done", { findings: findings.length, tools: tools.length });
  }

  return { findings, tools, scanStats };
}
