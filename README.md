# MergeSafe Scanner (V0 Core)

Offline-first deterministic scanner for MCP server codebases.

## Quickstart

```bash
pnpm install
pnpm test
pnpm -C packages/cli dev -- scan fixtures/node-unsafe-server
```

Example with explicit outputs:

```bash
pnpm -C packages/cli dev -- scan fixtures/node-unsafe-server --out-dir mergesafe-test --format json,sarif,md,html --fail-on none
```

Generated outputs:
- `mergesafe/report.json`
- `mergesafe/summary.md`
- `mergesafe/results.sarif`
- `mergesafe/report.html`

Default engines are `mergesafe,semgrep,gitleaks`. Missing Semgrep/Gitleaks binaries are auto-installed by default into `${HOME}/.mergesafe/tools` (override with `MERGESAFE_TOOLS_DIR`).

## Workspace packages

- `packages/cli`: `mergesafe scan <path>` command
- `packages/core`: canonical schema, dedupe, scoring/fail logic
- `packages/rules`: deterministic static rules + tool surface extraction
- `packages/report`: markdown and HTML reporting
- `packages/sarif`: SARIF 2.1.0 conversion

## CLI flags

- `--out-dir <dir>` default `mergesafe`
- `--format <csv>` default `json,html,sarif,md`
- `--mode fast|deep` default `fast`
- `--timeout <seconds>`
- `--concurrency <n>`
- `--fail-on critical|high|none` default `high`
- `--config <path>` (optional YAML)
- `--engines <csv|space-separated>` default `mergesafe,semgrep,gitleaks`
- `--auto-install <true|false>` default `true`
- `--no-auto-install` disable tool bootstrap
- `--redact`

Windows smoke test:

```bash
pnpm -C packages/cli dev -- scan fixtures/node-unsafe-server --out-dir mergesafe-test --fail-on none
```

Expected output files:
- `mergesafe-test/report.json`
- `mergesafe-test/summary.md`
- `mergesafe-test/results.sarif`
- `mergesafe-test/report.html`
