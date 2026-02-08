# MergeSafe Summary

Status: **PASS**

Grade: **F** (score 0)

## Totals
- Total findings: 10
- Critical: 2
- High: 5
- Medium: 3
- Low: 0
- Info: 0

## Engines
- mergesafe:ok

## Top Findings
- **CRITICAL** Command execution reachable from tool handlers (C:\MergeSafe\mergesafe-scanner\fixtures\node-unsafe-server\server.js:14)
- **CRITICAL** Dynamic tool registration from untrusted input (C:\MergeSafe\mergesafe-scanner\fixtures\node-unsafe-server\server.js:20)
- **HIGH** Destructive tools exposed without gating hints (C:\MergeSafe\mergesafe-scanner\fixtures\node-unsafe-server\server.js:8)
- **HIGH** Filesystem write with user-controlled paths (C:\MergeSafe\mergesafe-scanner\fixtures\node-unsafe-server\server.js:15)
- **HIGH** Network egress from tool handlers without allowlist (C:\MergeSafe\mergesafe-scanner\fixtures\node-unsafe-server\server.js:16)
