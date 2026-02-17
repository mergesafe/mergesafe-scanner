MergeSafe CLI

Multi-engine security scanner for MCP servers and code repositories. Runs locally and generates reproducible reports you can gate in CI.
    Scans repos and MCP/server code for risky patterns
    Produces reports: JSON / Markdown / HTML / SARIF
    Designed for deterministic output + CI gating

Requirements
Node.js >= 18

Install / Run
Run without installing (recommended)
npx mergesafe --help
npx mergesafe scan .

Install globally
npm i -g mergesafe
mergesafe --help
mergesafe scan .

Quick start

Scan the current folder and write outputs to ./out:

npx mergesafe scan . --out-dir ./out --format json,md,html,sarif


Scan a specific path:

npx mergesafe scan /path/to/repo --out-dir ./out

Common options
Output directory
npx mergesafe scan . --out-dir ./out

Formats

Choose one or more formats:

npx mergesafe scan . --format json
npx mergesafe scan . --format sarif
npx mergesafe scan . --format json,md,html,sarif

Fail-on gating

Use this in CI to fail the process when findings meet a threshold.

# never fail (useful for exploration)
npx mergesafe scan . --fail-on none

# examples (if supported by your CLI)
npx mergesafe scan . --fail-on high
npx mergesafe scan . --fail-on medium


Note: Exact thresholds depend on your CLI’s supported values. Run --help to see the current list.

List engines
npx mergesafe list-engines

Outputs

MergeSafe can emit:

report.json (machine-readable)

summary.md (human-friendly summary)

report.html (shareable report)

results.sarif (GitHub code scanning / SARIF viewers)

(Exact filenames may vary by your CLI flags; check --help.)

Examples

Scan the included fixture (if you have it locally):

npx mergesafe scan ./fixtures/node-unsafe-server --out-dir ./out --format json --fail-on none

License

Apache-2.0