# Changelog

## 0.1.0

- Default CLI engine set is now `mergesafe, semgrep, gitleaks, cisco, osv` with external engine smoke tests gated behind `RUN_EXTERNAL_ENGINES=1` for CI stability.
- Added tool-cache defaults and workflow wiring for `MERGESAFE_TOOLS_DIR` to keep external downloads optional.
- `results.sarif` is now produced as one merged SARIF 2.1.0 file with a single `runs[0]` MergeSafe run that contains canonical merged results.
- GitHub Action/workflow template now uses path-safe output discovery and guarded SARIF upload/PR comment steps.
