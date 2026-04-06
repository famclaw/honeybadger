# Contributing to HoneyBadger

HoneyBadger scans AI agent skills and MCP servers for security issues.
Help us make the AI agent ecosystem safer.

## Getting started

```bash
git clone https://github.com/famclaw/honeybadger
cd honeybadger
make build
make test
make self-check   # HoneyBadger scans itself
```

## Code structure

Every scanner lives in its own package under `internal/scanner/`:

- `internal/scanner/secrets/` -- gitleaks-powered secrets detection
- `internal/scanner/supplychain/` -- supply chain risk patterns + typosquatting
- `internal/scanner/cve/` -- osv.dev CVE scanner + dependency parser (8 lockfile formats)
- `internal/scanner/meta/` -- SKILL.md metadata validation
- `internal/scanner/attestation/` -- build provenance + cosign verification

Core types and shared utilities:

- `internal/scan/finding.go` -- `Finding`, `ParanoiaLevel`, `Options` structs
- `internal/scan/helpers.go` -- `WalkCode`, `Redact`, `EditDistance`, `IsBinaryFile`
- `internal/scan/scan.go` -- `RunAll` concurrent fan-in runner
- `internal/engine/engine.go` -- scanner list builder, verdict computation, tier detection
- `internal/testfixture/` -- 7 builder functions for test repos + mock OSV server

Entry points:

- `cmd/honeybadger/main.go` -- CLI pipeline
- `cmd/honeybadger/mcp.go` -- MCP server mode (JSON-RPC over stdio)

## Rules for changes

- Every scanner change needs a corresponding test fixture
- Fixtures build secrets at runtime (not hardcoded) to avoid GitHub push protection
- Run `make self-check` before submitting -- it scans HoneyBadger itself
- Tests: `make test` runs all unit tests, `go test -tags integration ./...` for integration

## Areas for contribution

- **New lockfile parsers** -- Cargo.lock, pnpm-lock.yaml, poetry.lock (add in `internal/scanner/cve/deps.go`)
- **Output formats** -- SARIF for GitHub Code Scanning, JUnit XML for CI dashboards
- **GitHub Action** -- `famclaw/honeybadger-action` wrapper for easy CI integration
- **Homebrew formula** -- `brew install honeybadger`
- **Scan benchmarks** -- detection rate and speed metrics
- **Allowlist config** for paranoid mode (known gap -- not yet defined)
- **Docstring coverage** (currently ~33%, needs improvement)
- **Additional typosquat dictionary** entries in supplychain scanner
- **Scanner improvements** -- new secret patterns, supply chain detection rules

## Pull requests

1. Fork the repo
2. Create a feature branch
3. Add tests -- every scanner change needs a test fixture
4. Run `make test` and `make self-check`
5. Open a PR against `main`

## License

MIT. Contributions are licensed under the same terms.
