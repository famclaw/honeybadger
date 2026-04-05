# HoneyBadger

Security scanner for skills, tools, and MCP servers used by AI assistant runtimes.

**HoneyBadger don't care. HoneyBadger checks anyway.**

## What it does

Before anything gets installed on a family home server running AI assistants, HoneyBadger checks it.

## Usage

### CLI

    honeybadger scan <repo-url> [flags]

    Flags:
      --paranoia string      off|minimal|family|strict|paranoid (default: family)
      --format string        ndjson|text (default: ndjson)
      --llm string           LLM endpoint override
      --db string            Path to audit trail file
      --installed-sha string SHA256 of installed version
      --installed-tool-hash  SHA256 of installed MCP tool definitions
      --force                Skip scan, exit 0
      --offline              Skip network calls, scan local only
      --path string          Subdirectory within repo to scan

### MCP Server

    honeybadger --mcp-server

Speaks MCP JSON-RPC over stdio. Exposes `honeybadger_scan` tool.

## What it checks

| Check | Scanner | Description |
|-------|---------|-------------|
| Secrets | gitleaks v8 | 800+ credential patterns, noise reduction |
| Supply chain | regex + typosquat | curl\|bash, eval, reverse shell, crypto mining, etc. |
| CVEs | osv.dev | Batch API across Go, npm, PyPI, Rust, Ruby, Maven |
| SKILL.md | meta checker | Declared vs actual permissions |
| Attestation | GitHub API | Build provenance, cosign, SHA256SUMS (strict/paranoid) |

## Paranoia levels

| Level | Scanners | LLM | Blocks on |
|-------|----------|-----|-----------|
| off | None | No | Nothing |
| minimal | secrets, cve | No | CRITICAL |
| family | secrets, cve, supplychain, meta | Yes | HIGH+ |
| strict | all + attestation | Yes | MEDIUM+ (WARN=FAIL) |
| paranoid | all + allowlist | Yes | LOW+ |

## Output

Newline-delimited JSON streamed to stdout. Events: progress, finding, cve, health, attestation, sandbox, result.

Exit codes: 0=PASS, 1=WARN, 2=FAIL, 3=error.

## Project structure

```
honeybadger/
├── cmd/honeybadger/
│   ├── main.go              # CLI entry point — full pipeline wiring
│   ├── mcp.go               # MCP server mode — JSON-RPC over stdio
│   └── mcp_test.go          # MCP server tests via in-process client
├── internal/
│   ├── engine/
│   │   ├── engine.go        # Verdict computation, tier/sandbox detection, scanner list builder
│   │   └── engine_test.go
│   ├── fetch/
│   │   ├── fetch.go         # Repo type, Route(), Fetcher interface
│   │   ├── fetch_test.go
│   │   ├── github.go        # GitHub fetcher
│   │   ├── gitlab.go        # GitLab fetcher
│   │   └── tarball.go       # Tarball fetcher
│   ├── report/
│   │   ├── types.go         # Emitter interface
│   │   ├── ndjson.go        # NDJSON streaming emitter
│   │   ├── ndjson_test.go
│   │   ├── text.go          # Human-readable text emitter
│   │   ├── text_test.go
│   │   ├── llm.go           # LLM prompt assembly + verdict calling
│   │   └── llm_test.go
│   ├── scan/
│   │   ├── finding.go       # Finding struct, severity constants, ParanoiaLevel, Options
│   │   ├── finding_test.go
│   │   ├── scan.go          # ScanFunc type, RunAll (concurrent runner with fan-in)
│   │   ├── scan_test.go
│   │   └── helpers.go       # WalkCode, IsPlaceholder, Redact, EditDistance, IsBinaryFile
│   ├── scanner/
│   │   ├── secrets/
│   │   │   ├── secrets.go       # Secrets scanner (gitleaks-powered)
│   │   │   └── secrets_test.go
│   │   ├── supplychain/
│   │   │   ├── supplychain.go   # Supply chain risk patterns + typosquat detection
│   │   │   └── supplychain_test.go
│   │   ├── cve/
│   │   │   ├── cve.go           # CVE scanner via osv.dev API
│   │   │   ├── deps.go          # Dependency parser (8 lockfile formats)
│   │   │   ├── cve_test.go
│   │   │   └── deps_test.go
│   │   ├── meta/
│   │   │   ├── meta.go          # SKILL.md meta scanner
│   │   │   └── meta_test.go
│   │   └── attestation/
│   │       ├── attestation.go   # Attestation verification scanner
│   │       └── attestation_test.go
│   ├── store/
│   │   ├── audit.go          # JSONL audit trail writer
│   │   └── audit_test.go
│   └── testfixture/
│       ├── fixtures.go       # Builder functions returning *fetch.Repo with in-memory files
│       ├── fixtures_test.go  # Smoke tests for all fixtures
│       └── mock_osv.go       # Mock osv.dev server for testing CVE scanner
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml
│       ├── codeql.yml
│       └── release.yml
├── docs/
│   ├── OPENCLAW.md           # Installation guide for FamClaw, OpenClaw, PicoClaw
│   └── EXAMPLES.md           # CLI and MCP usage examples
├── .gitignore
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── SECURITY.md
└── SKILL.md                  # AgentSkills manifest for skill registries
```

## Status

Wave 9 complete. Added installation and usage documentation:
- `docs/OPENCLAW.md` -- installation guide for FamClaw, OpenClaw, and PicoClaw runtimes
- `docs/EXAMPLES.md` -- CLI and MCP usage examples, NDJSON event format, exit codes, CI/CD

Wave 8 complete. Added test fixture package:
- `internal/testfixture/` with 7 builder functions returning `*fetch.Repo` for integration/E2E tests
- Fixtures: CleanRepo, SecretsRepo, SupplyChainRepo, CVERepo, MetaMismatchRepo, AttestationRepo, FullyCleanSkillRepo
- `WriteToDir` helper writes repo files to a temp directory for CLI subprocess tests
- Mock OSV server for testing CVE scanner without network
- All secrets built at runtime to avoid GitHub push protection

Previous waves:
- Each scanner in its own package under `internal/scanner/`
- Core types (Finding, Options, ParanoiaLevel) in `internal/scan/`
- Shared helpers (WalkCode, Redact, EditDistance) in `internal/scan/helpers.go`
- Concurrent runner in `internal/scan/scan.go`
- Scanner list builder in `internal/engine/` (avoids import cycles)
- All existing functionality preserved — pure refactor, zero behavior change
- Fetch layer (GitHub, GitLab, tarball, local)
- NDJSON and text reporters + LLM verdict
- Full CLI pipeline with tier/sandbox detection
- MCP server mode
- CI/CD: govulncheck, CodeQL, dependabot, release pipeline

## Building

    make build          # current platform
    make cross          # all 5 targets (linux arm64/armv7/amd64, darwin arm64/amd64)
    make test           # run all tests
    make self-check     # scan ourselves at strict paranoia

## License

AGPL-3.0 — same as [FamClaw](https://github.com/famclaw/famclaw).
