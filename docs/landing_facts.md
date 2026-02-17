# MergeSafe Scanner: Verified Landing-Page Facts

## 1) Product definition (verified)
MergeSafe Scanner is a local, multi-engine security scanner for MCP servers and related codebases that combines built-in deterministic rules with optional external engines (Semgrep, Gitleaks, Cisco mcp-scanner, OSV-Scanner, optional Trivy), merges findings into a canonical schema, and emits CI-friendly JSON/Markdown/HTML/SARIF outputs with separate policy-gate and scan-completeness statuses for enforcement in pipelines. It is aimed at security-conscious engineering teams shipping MCP servers/tools who need reproducible outputs and configurable CI gating without requiring source upload by default. 

---

## 2) Verified Facts

| Claim | Evidence | Notes (constraints/limits) |
|---|---|---|
| MergeSafe is a deterministic scanner for MCP server codebases. | `README.md` intro text; deterministic rules package description. | Deterministic language is present in docs and implemented via stable sorting/path normalization in core/rules. |
| CLI command is `mergesafe scan <path>`. | `packages/cli/src/index.ts` help text + argument parser usage error. | `packages/cli/README.md` contains some outdated command examples (see corrections). |
| Default engines are exactly: `mergesafe, semgrep, gitleaks, cisco, osv`. | `packages/core/src/index.ts` `DEFAULT_ENGINES`; CLI config resolution uses `DEFAULT_ENGINES`; action description/default behavior also states same list. | `trivy` is available but not in defaults. |
| Available engines include `trivy`. | `packages/core/src/index.ts` `AVAILABLE_ENGINES`; `packages/engines/src/index.ts` includes `TrivyAdapter` in `defaultAdapters`. | Trivy adapter currently generates artifacts but returns no mapped findings in current implementation. |
| Multi-engine orchestration is concurrent and merges canonical findings across engines. | `packages/engines/src/index.ts` `runEngines` worker queue/concurrency + final `mergeCanonicalFindings(findings)`. | Engine failures are captured in per-engine meta rather than crashing the whole scan. |
| Missing binaries are auto-installed by default (unless disabled). | CLI config: `autoInstall` default true; README states auto-install behavior; engine run path attempts `ensureAvailable` when missing and auto-install enabled. | Auto-install may download binaries from network. |
| Tool downloads are pinned and checksum-verifiable (`off|warn|strict`). | `packages/engines/src/toolManifest.ts` pinned versions + sha256 per artifact; `packages/engines/src/index.ts` verification helpers and mode handling; CLI/action expose `--verify-downloads`. | CLI default is `warn`; action default is `strict`. |
| Scanner emits JSON/MD/HTML/SARIF outputs. | CLI defaults include all 4 formats; `writeOutputs` writes `report.json`, `summary.md`, `report.html`, `results.sarif`; README examples list same files. | Output file creation depends on selected `--format`. |
| SARIF output is a single merged run (not per-engine runs) for deduped code-scanning UX. | `packages/sarif/src/index.ts` `mergeSarifRuns` comment and implementation with one merged run. | Contains MergeSafe properties and engine attribution metadata. |
| Result model separates policy gate from scan completeness (`gateStatus` vs `scanStatus`). | Core types `ScanStatus`, `GateStatus`, `ScanSummary`; `summarize` computes gate + scan status; README section “Scan completeness vs policy gate”. | This is a key messaging point and is explicitly implemented. |
| Exit codes: `0` pass, `2` gate fail, `3` scan-status enforcement fail; gate fail takes precedence. | `packages/cli/src/index.ts` `computeExitCode`; README exit code table and precedence explanation. | `process.exit(1)` remains for fatal CLI runtime errors in `main().catch`. |
| Deterministic rules detect specific MCP/security smells (MS001–MS019 subset) including exec taint, file-write taint, network egress without allowlist, secret logging, auth smells, unsafe defaults, metadata mismatch, dynamic tool registration, manifest risks. | `packages/rules/src/index.ts` + `packages/rules/src/js_taint.ts` + `packages/rules/src/tools_manifest.ts`. | Deep mode adds MS011 dynamic execution rule; manifest rules add MS012–MS019 and MS017/MS018 parse/integrity checks. |
| Path normalization supports relative/absolute output modes, defaulting to relative for reproducibility/privacy. | `packages/cli/src/index.ts` parses `--path-mode` default `relative`; core normalization functions normalize paths for output/fingerprints. | Relative paths avoid machine-specific absolute paths in default output. |
| GitHub Action is composite, runs Node 20 + pnpm, runs scanner from this repo source, can upload SARIF and comment PR. | `packages/action/action.yml` steps (`setup-node`, `pnpm`, run scan, conditional upload/comment). | Action runs `pnpm -C packages/cli dev -- scan ...` and sets tools cache in `runner.temp`. |
| Cisco adapter is explicitly labeled “offline-safe” and defaults auto mode to `known-configs` unless tools manifest found (then static). | `packages/engines/src/index.ts` `CiscoMcpAdapter` displayName + mode resolution logic + `MCP_SCANNER_OFFLINE=1`. | In known-configs mode it may scan local MCP client configs on runner, not necessarily repo files. |
| Fixtures intentionally include unsafe patterns and manifest capabilities that trigger findings. | `fixtures/node-unsafe-server/server.js`, `fixtures/node-unsafe-server/tools-list.json`, `fixtures/python-unsafe-server/server.py`; golden report with expected findings. | Useful for demo copy/examples, but should be clearly labeled fixture data. |

---

## 3) Landing Page Copy (ready to paste)

### Hero
**Headline:** Secure your MCP server code before merge.

**Subhead:** MergeSafe runs a local, multi-engine security scan (deterministic rules + optional external engines), merges findings into one canonical report, and gives you CI-ready pass/fail gating with SARIF support.

**3 bullets:**
- Multi-engine by default: MergeSafe + Semgrep + Gitleaks + Cisco + OSV (with optional Trivy).
- Deterministic outputs: normalized paths, stable finding ordering, and merged SARIF.
- CI controls that separate **policy gate** failures from **scan completeness** failures.

### Feature grid
1. **Multi-engine orchestration:** Runs selected engines concurrently and merges overlapping findings into canonical results.
2. **Deterministic built-in rules:** Detects MCP-specific risky patterns (exec/file/network/auth/metadata/manifest) without external services.
3. **Canonical finding schema:** Every finding includes severity, confidence, category, OWASP MCP mapping, evidence, remediation, and fingerprint.
4. **Policy + completeness model:** Reports both gate outcome (PASS/FAIL) and scan completion state (OK/PARTIAL/FAILED).
5. **Reproducible reporting:** Stable sorting and path normalization reduce machine/OS output drift.
6. **Multiple output formats:** JSON, Markdown summary, HTML report, and SARIF 2.1.0 from one scan.
7. **GitHub-native workflow support:** Upload SARIF to Code Scanning and optionally comment PR summaries.
8. **Pinned tool bootstrap:** Auto-install can fetch pinned tool versions and verify checksums.

### How it works
1. **Select target + config:** Run `mergesafe scan <path>` with optional config/engines/policy flags.
2. **Execute engines:** MergeSafe executes built-in deterministic rules and selected external adapters concurrently.
3. **Canonicalize + merge:** Findings are normalized, deduplicated/merged across engines, and scored.
4. **Write artifacts:** Generates selected outputs (JSON/MD/HTML/SARIF) and engine execution metadata.
5. **Gate CI:** Exit code reflects policy threshold and optional scan-completeness enforcement.

### Outputs
- **`report.json`**: Full machine-readable scan result (`meta`, `summary`, `findings`, engine statuses, per-finding evidence/remediation).
- **`summary.md`**: Human-readable totals, gate/scan status, engine table, and top findings.
- **`report.html`**: Shareable HTML report with status badges, engine notes, and findings.
- **`results.sarif`**: SARIF 2.1.0 single merged run for GitHub/code-scanning tools, including MergeSafe metadata and engine attribution.

### GitHub Action
Use the composite action in CI to scan repo paths, upload SARIF, and optionally comment PRs.

**Key inputs:**
- `path` (default `.`)
- `mode` (`standard`/`fast`, default `standard`)
- `fail_on` (default `high`)
- `engines` (empty = default set)
- `out_dir` (default `mergesafe`)
- `upload_sarif` (default `true`)
- `comment_pr` (default `false`)
- `config` (optional path)
- `verify_downloads` (`off|warn|strict`, default `strict`)

### FAQ
**Q1: Does MergeSafe upload my source code to a SaaS service by default?**  
A: Not by default. Scans run locally; however, tool bootstrap can download scanner binaries/databases when enabled.

**Q2: What engines run if I do nothing?**  
A: `mergesafe, semgrep, gitleaks, cisco, osv`.

**Q3: Is Trivy included by default?**  
A: No. Trivy is supported but only runs if explicitly selected (for example via `--engines trivy` or `all`).

**Q4: Can scans succeed when one engine fails?**  
A: Yes. Engine failures/skips are tracked in scan metadata; scan outputs are still written, and you can enforce completeness with `--fail-on-scan-status`.

**Q5: How do I fail CI only for severe findings?**  
A: Use `--fail-on high` (default) or `--fail-on critical`; use `--fail-on none` to disable severity gating.

**Q6: Can I fail CI when scans are partial?**  
A: Yes. Configure `--fail-on-scan-status partial|failed|any` to enforce scan completeness.

**Q7: Is the Cisco engine scanning my repo by default?**  
A: Not always. In auto mode without repo tools JSON, Cisco uses known-configs mode and may scan local MCP client configs on the runner.

**Q8: What formats can I export?**  
A: JSON, Markdown, HTML, and SARIF.

**Q9: Are tool downloads trusted?**  
A: Tool artifacts are pinned with checksums in the manifest; verification behavior depends on `verify-downloads` mode.

---

## 4) Configuration & Defaults

### Default engines (exact)
`mergesafe,semgrep,gitleaks,cisco,osv`

### Config format and key options
- CLI `--config` is documented as YAML and parsed with `YAML.parse`.
- Because YAML parser is used, JSON-formatted config files are also likely parseable, but this is **UNVERIFIED as a documented contract**.

Common options (from CLI resolve/help + README):
- `outDir`
- `format` (`json|html|sarif|md` list)
- `mode` (`standard|fast|deep`)
- `timeout`
- `concurrency`
- `failOn` (`critical|high|none`)
- `failOnScanStatus` (`none|partial|failed|any`)
- `autoInstall` / `no-auto-install`
- `verifyDownloads` (`off|warn|strict`)
- `pathMode` (`relative|absolute`)
- `maxFileBytes`
- `engines`
- `cisco.*` options (`mode`, `toolsPath`, `configPath`, `serverUrl`, `stdioCommand`, `stdioArgs`, `headers`, `bearerToken`, `analyzers`)

### Offline / network behavior
- Core scanning executes locally.
- Network may be used when:
  - Auto-install downloads missing engine binaries from pinned URLs (Semgrep/Gitleaks/OSV/Trivy manifest URLs).
  - External tools themselves may require/update vulnerability databases (for example OSV/Trivy behavior is tool-dependent).
  - Cisco `remote` mode needs `serverUrl`.
- Cisco adapter sets `MCP_SCANNER_OFFLINE=1` in execution env and is labeled offline-safe.

### Exit codes + gating behavior
- `0`: gate pass + no scan-status enforcement violation
- `2`: policy gate fail (severity threshold)
- `3`: scan-status enforcement fail
- Precedence: gate fail (`2`) wins over scan-status fail (`3`).

---

## 5) Do NOT Claim (misleading/false for current repo)

1. **“MergeSafe is fully offline and never touches the network.”**  
   False: auto-install and some engines can download artifacts/databases.

2. **“All supported engines run by default, including Trivy.”**  
   False: Trivy is available but not in `DEFAULT_ENGINES`.

3. **“Any engine failure always fails the scan.”**  
   False: failures/skips are captured; outputs can still be written unless policy/completeness settings enforce failure.

4. **“Cisco always scans repository source code.”**  
   False: auto mode can default to known-configs scanning local MCP client configs.

5. **“CLI supports `--fail-on medium`.”**  
   Misleading for this code: parser/help/readme root only support `critical|high|none`.

6. **“Primary command is `mergesafe list-engines`.”**  
   Misleading for this CLI implementation: supported form is `mergesafe --list-engines`.

7. **“Trivy findings are fully normalized into canonical findings today.”**  
   Not supported by current adapter implementation (it currently returns artifacts but empty findings).

---

## 6) Suggested landing-page/documentation corrections

1. **Fix CLI docs for engine listing syntax**  
   - **Change:** Replace `npx mergesafe list-engines` with `npx mergesafe --list-engines`.  
   - **Why:** CLI parser/help only defines `--list-engines` as supported command path.  
   - **Evidence:** `packages/cli/src/index.ts` parser/help; current mismatch in `packages/cli/README.md`.

2. **Remove/clarify `--fail-on medium` examples**  
   - **Change:** Use only `critical|high|none` examples.  
   - **Why:** Current help text and README root define only those values.  
   - **Evidence:** `packages/cli/src/index.ts` help text; `README.md` CLI flags; contradictory line in `packages/cli/README.md`.

3. **Clarify Cisco default behavior in marketing copy**  
   - **Change:** Add note: “Cisco is offline-safe and may scan known local MCP client configs unless static repo tools manifest is provided.”  
   - **Why:** Prevents users assuming Cisco always scans repository source.  
   - **Evidence:** `packages/engines/src/index.ts` Cisco mode resolution and known-configs behavior; report notes in `packages/report/src/index.ts`.

4. **Avoid claiming “fully offline by default” without caveat**  
   - **Change:** State “local scan by default; optional bootstrap/downloads may access network.”  
   - **Why:** Auto-install/tool updates can fetch binaries/databases.  
   - **Evidence:** README auto-install language; tool manifest download URLs; engine ensure/install logic.

5. **Avoid implying Trivy contributes canonical findings today**  
   - **Change:** Phrase as “Trivy integration available (artifact generation), optional engine.”  
   - **Why:** Current adapter returns empty findings array.  
   - **Evidence:** `packages/engines/src/index.ts` `TrivyAdapter.run`.

---

## Quickstart snippets (verified)

### CLI quickstart
```bash
npx mergesafe scan . \
  --out-dir mergesafe \
  --format json,html,sarif,md \
  --fail-on high
```

### GitHub Action quickstart
```yaml
name: MergeSafe
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mergesafe/mergesafe-scanner/packages/action@main
        with:
          path: .
          mode: standard
          fail_on: high
          upload_sarif: true
```

> Note: action reference path/ref should match how you publish/version this action. The input names/defaults above are verified from `packages/action/action.yml`.

