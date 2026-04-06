<p align="center">
  <img src="assets/mascot.png" alt="HoneyBadger — kicking snakes, protecting your claw runtimes" width="600">
</p>

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
│   ├── mcp_test.go          # MCP server tests via in-process client
│   ├── integration_test.go  # CLI + MCP integration tests (build tag: integration)
│   └── e2e_test.go          # E2E stdio MCP server subprocess tests
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
│   ├── CLAUDE_CODE.md        # Claude Code integration guide (MCP config, hooks)
│   ├── EXAMPLES.md           # CLI and MCP usage examples
│   └── docs_test.go          # Doc validation tests (11 functions, 35 checks)
├── .gitignore
├── Dockerfile                # Multi-stage distroless image for honeybadger
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── SECURITY.md
└── SKILL.md                  # AgentSkills manifest for skill registries
```

## Status

Wave 10 complete. Supply chain hardening, integration docs, and doc validation tests:
- Reproducible builds (`-trimpath -buildvcs=false`)
- Cosign signature verification step in release pipeline
- SBOM switched to SPDX format, attested alongside binaries
- Multi-arch OCI images built and pushed to GHCR, signed with cosign
- SECURITY.md corrected to match actual practices (SLSA L2, not L3)
- CI security checks use `continue-on-error` instead of `|| true` (visible warnings)
- `go mod tidy` drift check in CI
- `docs/OPENCLAW.md` rewritten with real FamClaw config.yaml, Docker usage, verification commands
- `docs/CLAUDE_CODE.md` -- dedicated Claude Code integration guide (MCP config, hooks, Docker)
- `docs/docs_test.go` validates all docs stay in sync with source (35 checks):
  paranoia levels, CLI flags, MCP params, env vars, binary targets, response schema, Claude Code config

Previous waves:
- Installation and usage documentation (`docs/OPENCLAW.md`, `docs/EXAMPLES.md`)
- Test fixture package with 7 builders, mock OSV server
- Each scanner in its own package under `internal/scanner/`
- Core types, shared helpers, concurrent runner, scanner list builder
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

AGPL-3.0-only
