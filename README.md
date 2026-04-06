<p align="center">
  <img src="assets/mascot.png" alt="HoneyBadger — kicking snakes, protecting your claw runtimes" width="600">
</p>

# HoneyBadger

Security scanner for skills, tools, and MCP servers used by AI assistant runtimes.

**HoneyBadger don't care. HoneyBadger checks anyway.**

## What it does

Before anything gets installed on a family home server running AI assistants, HoneyBadger checks it.

## Install

    # Go install (requires Go 1.22+)
    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

    # Binary download (Linux amd64)
    curl -fsSL https://github.com/famclaw/honeybadger/releases/latest/download/honeybadger-linux-amd64 \
      -o honeybadger && chmod +x honeybadger

    # Docker
    docker pull ghcr.io/famclaw/honeybadger:latest

All platforms: [Releases](https://github.com/famclaw/honeybadger/releases/latest) —
Linux (amd64, arm64, armv7), macOS (arm64, amd64).
Verify downloads: see [SECURITY.md](SECURITY.md).

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
| Secrets | gitleaks v8 | 800+ credential patterns, noise reduction for test files |
| CVEs | osv.dev | Batch API across Go, npm, PyPI, Rust, Ruby, Maven (8 lockfile formats) |
| curl\|bash | supplychain | Downloads and executes remote scripts |
| eval remote | supplychain | Evaluates remotely fetched code |
| Reverse shell | supplychain | nc/netcat/bash reverse shell patterns |
| Crypto mining | supplychain | Coinhive, xmrig, stratum+tcp patterns |
| Data exfil | supplychain | Webhook/requestbin exfiltration endpoints |
| Typosquat | supplychain | Edit-distance check against popular package names |
| SKILL.md fields | meta | Required fields and format validation |
| Permission mismatch | meta | Declared vs actual network/filesystem/exec usage |
| Build provenance | attestation | GitHub Attestation API + workflow check (strict+) |
| Cosign/SHA256 | attestation | Cosign signatures and checksum files present (strict+) |

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
├── .goreleaser.yml           # GoReleaser config: builds, signing, Docker, SBOM, changelog
├── Dockerfile                # Multi-stage distroless image (local dev)
├── Dockerfile.goreleaser     # GoReleaser Docker image (pre-built binary)
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── SECURITY.md
└── SKILL.md                  # AgentSkills manifest for skill registries
```

## Status

Wave 11 complete. GoReleaser migration + AI release notes:
- Release pipeline migrated to GoReleaser v2 (`.goreleaser.yml`)
- Cosign keyless signing of checksums and Docker manifests
- SPDX SBOM per binary via Syft
- Multi-arch Docker images (amd64 + arm64) pushed to GHCR, signed
- AI-powered release notes via Claude API (Haiku) — summarizes commits into user-facing highlights
- GitHub build provenance attestation for all binaries and SBOMs
- Self-check gate: HoneyBadger scans itself at strict paranoia before release
- `make release-dry` for local GoReleaser testing

Wave 10: Supply chain hardening, integration docs, doc validation tests
- SKILL.md rewritten for AgentSkills open standard (Claude Code + OpenClaw)
- `docs/OPENCLAW.md` -- OpenClaw integration guide
- `docs/CLAUDE_CODE.md` -- Claude Code integration guide
- `docs/docs_test.go` validates all docs stay in sync with source (35 checks)

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

    make build              # current platform
    make cross              # all 5 targets (linux arm64/armv7/amd64, darwin arm64/amd64)
    make test               # run all tests
    make self-check         # scan ourselves at strict paranoia (requires prior release)
    make self-check-bootstrap  # scan at minimal paranoia (for initial releases only)
    make release-dry        # test GoReleaser locally (snapshot, no publish)

## Release Checklist

1. `make self-check` passes at strict paranoia (or `self-check-bootstrap` for first release)
2. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
3. GoReleaser builds, signs, and publishes via `.github/workflows/release.yml`
4. Verify release: see [SECURITY.md](SECURITY.md#verifying-release-artifacts)
5. Set GitHub topics: `security`, `mcp`, `supply-chain`, `scanner`, `agentskills`, `golang`

## License

AGPL-3.0-only
