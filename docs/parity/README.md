# Parity audit

This directory stores source-of-truth parity audit artifacts generated from the built CLI/core outputs and selected docs metadata.

## Purpose

- Capture current behavior and defaults without changing runtime behavior.
- Provide deterministic artifacts for review in docs-parity PRs.
- Keep this PR focused on audit tooling; docs edits can happen in a follow-up PR.

## Commands

- `pnpm parity` verifies committed parity artifacts are up to date.
- `pnpm parity:update` regenerates `source-of-truth.md` and `source-of-truth.json`.

## PR sequencing

- PR-A (this phase): add tooling and audit artifacts only.
- PR-B (follow-up): apply doc text changes based on the audit.
