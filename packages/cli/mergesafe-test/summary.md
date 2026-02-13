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


## Top Findings
- **CRITICAL** Command execution from user-controlled input (server.js:14) — Found by: MergeSafe deterministic rules
- **CRITICAL** Dynamic tool registration from untrusted input (server.js:20) — Found by: MergeSafe deterministic rules
- **CRITICAL** Dangerous tool capability: arbitrary command execution exposed (tools-list.json:4) — Found by: MergeSafe deterministic rules
- **HIGH** Destructive tools exposed without gating hints (server.js:8) — Found by: MergeSafe deterministic rules
- **HIGH** Missing auth middleware smell on HTTP MCP endpoints (server.js:12) — Found by: MergeSafe deterministic rules
