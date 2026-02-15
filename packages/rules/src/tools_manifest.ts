// packages/rules/src/tools_manifest.ts
import fs from "node:fs";
import path from "node:path";
import type { RawFinding } from "@mergesafe/core";

export interface ToolSurface {
  name: string;
  hints: string[];
  capabilities: string[];
  filePath: string; // stable repo-relative POSIX path
}

export type ManifestTool = {
  name?: string;
  description?: string;
  inputSchema?: any;
  annotations?: Record<string, any>;
};

const TOOLS_MANIFEST_BASENAMES = [
  // keep in sync with index.ts skip list (superset is fine)
  "tools-list.json",
  "tool-list.json",
  "tools.json",
  "mcp-tools.json",
  "mcp.tools.json",
  "tools.manifest.json",
];

function toPosix(p: string): string {
  return String(p ?? "").replace(/\\/g, "/");
}

function stableRelPath(targetPath: string, absPath: string): string {
  const targetAbs = path.resolve(targetPath);
  const abs = path.resolve(absPath);

  let rel = path.relative(targetAbs, abs);
  if (!rel) rel = path.basename(abs);

  rel = rel.replace(/^[.][\\/]/, "");
  return toPosix(rel);
}

/**
 * Finds a tools manifest in the repo root.
 * Prefer canonical filenames, then fall back to "likely" JSON candidates.
 */
export function findToolsManifestPath(targetPath: string): string | undefined {
  const targetAbs = path.resolve(targetPath);

  for (const base of TOOLS_MANIFEST_BASENAMES) {
    const p = path.resolve(targetAbs, base);
    try {
      if (fs.existsSync(p) && fs.statSync(p).isFile()) return p;
    } catch {
      // ignore
    }
  }

  // bounded fallback: repo root only, deterministic order
  try {
    const entries = fs.readdirSync(targetAbs, { withFileTypes: true });
    const files = entries
      .filter((e) => e.isFile())
      .map((e) => e.name)
      .sort((a, b) => a.localeCompare(b)); // deterministic

    for (const nameRaw of files) {
      const name = nameRaw.toLowerCase();
      if (!name.endsWith(".json")) continue;
      if (
        name.includes("tools") &&
        (name.includes("mcp") || name.includes("tool")) &&
        !name.includes("package-lock") &&
        !name.includes("pnpm-lock")
      ) {
        return path.resolve(targetAbs, nameRaw);
      }
    }
  } catch {
    // ignore
  }

  return undefined;
}

function readTextSafe(p: string): string {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
}

function safeJsonParse(text: string): { ok: boolean; value?: any } {
  const t = String(text || "").trim().replace(/^\uFEFF/, ""); // strip BOM if present
  if (!t) return { ok: false };
  try {
    return { ok: true, value: JSON.parse(t) };
  } catch {
    return { ok: false };
  }
}

function normalizeManifestTools(raw: any): ManifestTool[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw as ManifestTool[];
  if (Array.isArray(raw.tools)) return raw.tools as ManifestTool[];
  if (Array.isArray(raw.items)) return raw.items as ManifestTool[];
  if (Array.isArray(raw.data)) return raw.data as ManifestTool[];
  return [];
}

function lineOf(content: string, pattern: RegExp): number {
  const idx = content.search(pattern);
  if (idx < 0) return 1;
  return content.slice(0, idx).split(/\r?\n/).length;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stringifySchemaBrief(schema: any): string {
  try {
    if (!schema) return "";
    const props =
      schema?.properties && typeof schema.properties === "object" ? Object.keys(schema.properties) : [];
    const req = Array.isArray(schema?.required) ? schema.required : [];
    const bits: string[] = [];
    if (props.length)
      bits.push(`props=[${props.slice(0, 12).join(", ")}${props.length > 12 ? ", ..." : ""}]`);
    if (req.length)
      bits.push(`required=[${req.slice(0, 12).join(", ")}${req.length > 12 ? ", ..." : ""}]`);
    return bits.join(" ");
  } catch {
    return "";
  }
}

function schemaTextLower(schema: any): string {
  try {
    return JSON.stringify(schema ?? {}).toLowerCase();
  } catch {
    return "";
  }
}

/** Detects if a hint keyword is mentioned in a NEGATED way (so we should NOT treat it as protection). */
function isNegated(descLower: string, keyword: string): boolean {
  const kw = escapeRegExp(keyword);
  return new RegExp(`\\b(no|without|lacks?|missing|not)\\s+${kw}\\b`, "i").test(descLower);
}

export function inferToolCapabilitiesFromManifest(t: ManifestTool): string[] {
  const name = String(t.name || "").toLowerCase();
  const desc = String(t.description || "").toLowerCase();
  const st = schemaTextLower(t.inputSchema);

  const caps = new Set<string>();

  // exec
  if (
    name.includes("exec") ||
    name.includes("shell") ||
    name.includes("command") ||
    desc.includes("arbitrary system command") ||
    desc.includes("shell command") ||
    desc.includes("execute any") ||
    desc.includes("runs an arbitrary") ||
    st.includes('"command"') ||
    st.includes("argv") ||
    st.includes("powershell") ||
    st.includes("bash")
  ) {
    caps.add("exec");
  }

  // fs read/write
  const mentionsPath =
    name.includes("file") ||
    name.includes("path") ||
    name.includes("read") ||
    name.includes("write") ||
    desc.includes("file path") ||
    desc.includes("reads the contents") ||
    desc.includes("write") ||
    st.includes('"path"') ||
    st.includes("filepath") ||
    st.includes('"filename"');

  if (mentionsPath) {
    const looksWrite =
      name.includes("write") ||
      desc.includes("write") ||
      desc.includes("append") ||
      st.includes("write") ||
      st.includes("append") ||
      st.includes('"dest"') ||
      st.includes('"output"');
    caps.add(looksWrite ? "fs-write" : "fs-read");
  }

  // net egress
  if (
    name.includes("http") ||
    name.includes("fetch") ||
    name.includes("request") ||
    desc.includes("fetches any url") ||
    desc.includes("supports arbitrary headers") ||
    desc.includes("internal hosts") ||
    st.includes('"url"') ||
    st.includes('"uri"') ||
    st.includes('"endpoint"') ||
    st.includes('"headers"') ||
    st.includes("requestheaders") ||
    st.includes('"method"') ||
    st.includes('"host"') ||
    st.includes('"hostname"')
  ) {
    caps.add("net-egress");
  }

  // secrets
  if (
    name.includes("token") ||
    name.includes("secret") ||
    name.includes("apikey") ||
    desc.includes("token") ||
    desc.includes("api key") ||
    desc.includes("secret") ||
    st.includes("token") ||
    st.includes("secret") ||
    st.includes("api_key") ||
    st.includes("apikey")
  ) {
    caps.add("secrets");
  }

  return Array.from(caps);
}

export function inferHintsFromManifest(t: ManifestTool): string[] {
  const hints = new Set<string>();
  const descLower = String(t.description || "").toLowerCase();
  const ann = t.annotations && typeof t.annotations === "object" ? t.annotations : {};
  const st = schemaTextLower(t.inputSchema);

  const hasAllowlistMention =
    /(allow[- ]?list|whitelist|allowed hosts|approved hosts|domain allowlist)/i.test(descLower) ||
    ann.allowlist === true ||
    st.includes("allowlist") ||
    st.includes("allowedhosts") ||
    st.includes("alloweddomains") ||
    st.includes("whitelist") ||
    st.includes("domains") ||
    st.includes("hosts");

  const hasAuthMention =
    /(auth|jwt|api[- ]?key|apikey|requires authentication|bearer)/i.test(descLower) ||
    ann.requiresAuth === true;

  const hasConfirmMention =
    /(confirm|approval|approve|human review|requires confirmation)/i.test(descLower) ||
    ann.requiresConfirmation === true;

  if (descLower.includes("read-only") || descLower.includes("readonly") || ann.readOnly === true) {
    hints.add("readOnlyHint");
  }
  if (descLower.includes("idempotent") || ann.idempotent === true) hints.add("idempotentHint");
  if (descLower.includes("destructive") || ann.destructive === true) hints.add("destructiveHint");

  if (hasAllowlistMention && !isNegated(descLower, "allowlist") && !isNegated(descLower, "allow-list")) {
    hints.add("allowlist");
  }
  if (hasAuthMention && !isNegated(descLower, "auth") && !isNegated(descLower, "authentication")) {
    hints.add("auth");
  }
  if (hasConfirmMention && !isNegated(descLower, "confirm") && !isNegated(descLower, "approval")) {
    hints.add("confirm");
  }

  return Array.from(hints);
}

export function loadToolsManifest(targetPath: string): {
  manifestPathAbs: string;
  manifestPath: string; // stable repo-relative POSIX (for findings/output)
  content: string;
  tools: ManifestTool[];
  parseOk: boolean;
} | undefined {
  const manifestPathAbs = findToolsManifestPath(targetPath);
  if (!manifestPathAbs) return undefined;

  const content = readTextSafe(manifestPathAbs);
  const parsed = safeJsonParse(content);
  const tools = normalizeManifestTools(parsed.value);

  return {
    manifestPathAbs,
    manifestPath: stableRelPath(targetPath, manifestPathAbs),
    content,
    tools,
    parseOk: parsed.ok,
  };
}

function mkManifestFinding(args: {
  ruleId: string;
  title: string;
  severity: RawFinding["severity"];
  filePath: string;
  content: string;
  toolName: string;
  evidence: string;
  remediation: string;
  tags: string[];
  category?: string;
  owasp?: string;
}): RawFinding {
  const pattern = args.toolName ? new RegExp(escapeRegExp(args.toolName), "i") : /./;
  const findingLine = lineOf(args.content, pattern);
  return {
    ruleId: args.ruleId,
    title: args.title,
    severity: args.severity,
    confidence: "medium",
    category: args.category ?? "mcp-security",
    owaspMcpTop10: args.owasp ?? "MCP-A05",
    filePath: args.filePath,
    line: findingLine,
    evidence: args.evidence,
    evidencePayload: {
      ruleId: args.ruleId,
      matchType: "manifest",
      matchSummary: args.evidence.slice(0, 160),
      locations: [{ filePath: args.filePath, line: findingLine }],
    },
    remediation: args.remediation,
    references: ["https://owasp.org"],
    tags: args.tags,
  };
}

export function emitToolsManifestFindings(
  targetPath: string,
  pushFinding: (f: RawFinding) => void
): ToolSurface[] {
  const loaded = loadToolsManifest(targetPath);
  if (!loaded) return [];

  const { manifestPath, content, tools, parseOk } = loaded;
  const surfaces: ToolSurface[] = [];

  // Parse failed -> MS017
  if (!parseOk && content.trim()) {
    pushFinding(
      mkManifestFinding({
        ruleId: "MS017",
        title: "Tools manifest present but JSON could not be parsed",
        severity: "medium",
        filePath: manifestPath,
        content,
        toolName: "tools",
        evidence: "Found a tools manifest but failed to parse JSON.",
        remediation:
          "Ensure the manifest is valid JSON (no trailing commas/comments/partial output). If it is generated, write atomically and validate JSON before saving.",
        tags: ["tool-manifest", "integrity", "debug"],
        category: "tooling",
        owasp: "MCP-A09",
      })
    );
    return [];
  }

  // Parsed but zero tools -> MS018
  if (parseOk && tools.length === 0) {
    pushFinding(
      mkManifestFinding({
        ruleId: "MS018",
        title: "Tools manifest parsed but contains zero tools",
        severity: "medium",
        filePath: manifestPath,
        content,
        toolName: "tools",
        evidence: "Tools manifest contains no tool entries.",
        remediation:
          "Verify your manifest shape: it should be an array, or an object with a `tools`/`items`/`data` array. Confirm the generator is discovering tools and writing them into the file.",
        tags: ["tool-manifest", "integrity", "debug"],
        category: "tooling",
        owasp: "MCP-A09",
      })
    );
    return [];
  }

  for (const tool of tools) {
    const name = String(tool?.name || "unknown");
    const desc = String(tool?.description || "");
    const caps = inferToolCapabilitiesFromManifest(tool);
    const hints = inferHintsFromManifest(tool);

    // ✅ stable file path
    surfaces.push({ name, hints, capabilities: caps, filePath: manifestPath });

    const evidence = `${name}: ${desc}${
      tool?.inputSchema ? ` | schema ${stringifySchemaBrief(tool.inputSchema)}` : ""
    }`.trim();

    const risky =
      caps.includes("exec") ||
      caps.includes("fs-read") ||
      caps.includes("fs-write") ||
      caps.includes("net-egress");

    const hasSomeGating = hints.includes("auth") || hints.includes("confirm") || hints.includes("allowlist");

    if (caps.includes("exec")) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS012",
          title: "Dangerous tool capability: arbitrary command execution exposed",
          severity: "critical",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "Tool indicates command execution capability.",
          remediation:
            "Do not expose arbitrary command execution tools to untrusted callers. Remove shell execution, enforce strict allowlists, require strong auth + approvals, and sandbox execution.",
          tags: ["tool-manifest", "exec", "policy"],
          category: "injection",
          owasp: "MCP-A03",
        })
      );
    }

    if (caps.includes("fs-read") && !hints.includes("allowlist")) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS013",
          title: "Dangerous tool capability: arbitrary file read without allowlist",
          severity: "high",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "Tool indicates file read capability without allowlist hints.",
          remediation:
            "Restrict reads to allowlisted directories. Normalize paths, block absolute paths and traversal, enforce auth, and audit access.",
          tags: ["tool-manifest", "fs-read", "policy"],
          category: "filesystem",
          owasp: "MCP-A04",
        })
      );
    }

    if (caps.includes("fs-write") && !hints.includes("allowlist")) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS019",
          title: "Dangerous tool capability: arbitrary file write without allowlist",
          severity: "critical",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "Tool indicates file write capability without allowlist hints.",
          remediation:
            "Restrict writes to allowlisted directories. Normalize paths, block absolute paths and traversal, enforce auth + approvals, and avoid user-chosen destinations/filenames.",
          tags: ["tool-manifest", "fs-write", "policy"],
          category: "filesystem",
          owasp: "MCP-A04",
        })
      );
    }

    if (caps.includes("net-egress") && !hints.includes("allowlist")) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS014",
          title: "Dangerous tool capability: unrestricted network egress without allowlist",
          severity: "high",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "Tool indicates network egress capability without allowlist hints.",
          remediation:
            "Enforce egress allowlists (hosts/schemes/ports). Block private/link-local ranges by default. Limit user-controlled headers. Require auth + approvals.",
          tags: ["tool-manifest", "net-egress", "policy"],
          category: "network",
          owasp: "MCP-A06",
        })
      );
    }

    if ((/log/i.test(name) || /debug/i.test(desc) || /print/i.test(desc)) && caps.includes("secrets")) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS015",
          title: "Dangerous tool behavior: token/secret logging helper present",
          severity: "high",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "Tool indicates debug logging of secrets/tokens.",
          remediation:
            "Remove secret/token logging tools from production. If needed locally, gate behind build flags, redact outputs, and ensure secrets never reach logs.",
          tags: ["tool-manifest", "secrets", "logging", "policy"],
          category: "secrets",
          owasp: "MCP-A02",
        })
      );
    }

    if (risky && !hasSomeGating) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS016",
          title: "High-risk tool exposed without gating hints (auth/allowlist/approval)",
          severity: "high",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "High-risk tool capability without gating hints.",
          remediation:
            "Add explicit gating: authentication, authorization scopes, approvals/confirmations, and allowlists. Document constraints in tool metadata and enforce them in code.",
          tags: ["tool-manifest", "gating", "policy"],
          category: "authn",
          owasp: "MCP-A01",
        })
      );
    }

    const descLower = desc.toLowerCase();
    const claimsReadOnly =
      descLower.includes("read-only") || descLower.includes("readonly") || hints.includes("readOnlyHint");
    const impliesMutate = caps.includes("exec") || caps.includes("fs-write") || caps.includes("net-egress");
    if (claimsReadOnly && impliesMutate) {
      pushFinding(
        mkManifestFinding({
          ruleId: "MS009",
          title: "Tool descriptions claim read-only but tool surface suggests exec/write/egress",
          severity: "medium",
          filePath: manifestPath,
          content,
          toolName: name,
          evidence: evidence || "Read-only claim conflicts with risky capabilities.",
          remediation:
            "Align tool metadata with actual capabilities. If tool can write/egress/exec, remove read-only claims and enforce strict gating.",
          tags: ["tool-manifest", "tool-metadata"],
          category: "integrity",
          owasp: "MCP-A09",
        })
      );
    }
  }

  return surfaces;
}
