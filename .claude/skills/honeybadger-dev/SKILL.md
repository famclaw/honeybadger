---
name: honeybadger-dev
description: How to add a scanner, lockfile parser, or rule to HoneyBadger, plus the test-fixture and self-check requirements. Use when extending scanners or contributing to honeybadger.
---

# HoneyBadger — extending scanners

## Adding a scanner
- New scanner = its own package under `internal/scanner/<name>/`.
- Register it in `internal/engine/engine.go` (scanner list + verdict weighting).
- Ship a matching fixture in `internal/testfixture/` — fixtures build secrets **at runtime** (never hardcoded) so GitHub push protection doesn't reject the push.

## Common extensions
- New lockfile parser (Cargo.lock, pnpm-lock.yaml, poetry.lock): add in `internal/scanner/cve/deps.go`.
- New supply-chain rule / secret pattern: add YAML under `rules/` (embedded via `rules/embed.go`).
- Typosquat dictionary entries: `internal/scanner/supplychain`.
- New test fixture: add to `internal/testfixture/` with secrets built at runtime.

## Before submitting
`make build` · `make test` · `make self-check` (scans itself) · `go test -tags integration ./...`. Open the PR against `main`.
