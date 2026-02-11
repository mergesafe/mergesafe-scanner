# MergeSafe Summary

Scan: **Completed**
Policy gate: **DISABLED** (failOn=none; failOn=none (policy gate disabled))
Risk grade: **F** (score 0)

## Totals
- Total findings: 17
- Critical: 3
- High: 11
- Medium: 3
- Low: 0
- Info: 0

## Engines
| Engine | Version | Status | Duration (ms) | Notes |
|---|---|---|---:|---|
| MergeSafe deterministic rules (mergesafe) | builtin | ok | 36 | Built in - no install required. |
| Semgrep (local rules only) (semgrep) | 1.151.0 | ok | 6551 | Auto-install semgrep into MergeSafe tools cache or install semgrep manually. |
| Gitleaks (gitleaks) | 8.30.0 | ok | 1314 | Auto-install gitleaks into MergeSafe tools cache or install gitleaks manually. |
| Cisco mcp-scanner (offline-safe) (cisco) | unknown | ok | 3770 | Cisco scanned MCP client config(s) from known locations on this machine (not repo source). Validate relevance to the project. Auto-install cisco-ai-mcp-scanner into MergeSafe tools cache or install it manually (CLI: mcp-scanner). |
| OSV-Scanner (osv) | osv-scanner version: 2.3.2
osv-scalibr version: 0.4.1
commit: e2a5d93abd9c85d068755973f014d28d6cec02c1
built at: 2026-01-15T01:08:54Z | ok | 181 | Auto-install osv-scanner into MergeSafe tools cache or install osv-scanner manually. |


## Cisco note
Cisco is **offline-safe by default** in MergeSafe. When it runs via **known-configs**, it scans MCP client configs on the machine (Cursor/Windsurf/VS Code, etc.), which may be unrelated to the repo.

- If you want Cisco to scan the repo deterministically: use **static tools JSON** (e.g. `--cisco-tools tools-list.json`).
- If Cisco shows **skipped**, that is expected when no configs/tools are available.

## Top Findings
- **CRITICAL** Command execution from user-controlled input (C:/MergeSafe/mergesafe-scanner/fixtures/node-unsafe-server/server.js:14) — Found by: MergeSafe deterministic rules, Semgrep (local rules only) ✅ Multi-engine confirmed
- **CRITICAL** Dynamic tool registration from untrusted input (C:/MergeSafe/mergesafe-scanner/fixtures/node-unsafe-server/server.js:20) — Found by: MergeSafe deterministic rules
- **CRITICAL** Dangerous tool capability: arbitrary command execution exposed (C:/MergeSafe/mergesafe-scanner/fixtures/node-unsafe-server/tools-list.json:4) — Found by: MergeSafe deterministic rules
- **HIGH** Destructive tools exposed without gating hints (C:/MergeSafe/mergesafe-scanner/fixtures/node-unsafe-server/server.js:8) — Found by: MergeSafe deterministic rules
- **HIGH** Missing auth middleware smell on HTTP MCP endpoints (C:/MergeSafe/mergesafe-scanner/fixtures/node-unsafe-server/server.js:12) — Found by: MergeSafe deterministic rules
