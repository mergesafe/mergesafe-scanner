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
- `--redact`
