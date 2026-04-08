<p align="center">
  <img src="assets/mascot.png" alt="HoneyBadger — kicking snakes, protecting your claw runtimes" width="600">
</p>

# HoneyBadger

Security scanner for skills, tools, and MCP servers used by AI assistant runtimes.

**HoneyBadger don't care. HoneyBadger checks anyway.**

## What it does

Before anything gets installed on a family home server running AI assistants, HoneyBadger checks it.
HoneyBadger performs static analysis only -- it reads source code and metadata but never executes the scanned code.

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

### Piped input

    cat SKILL.md | honeybadger scan -

Reads from stdin and scans it as a single file (`SKILL.md` by default).
Input is capped at 10 MB.

### Suppressing findings

Place a `.honeybadgerignore` file in your repository root. Each line suppresses
findings by rule ID, optionally constrained by a glob pattern or snippet SHA256:

    # Suppress all findings for a rule
    SECRET_IN_CODE

    # Suppress only in test fixtures
    SECRET_IN_CODE *.test.yaml

    # Suppress a specific snippet by SHA256
    SECRET_IN_CODE sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Suppressed findings are excluded from the verdict. A `suppression_summary`
NDJSON event is emitted when findings are suppressed. In text mode, a summary
line is printed after the verdict.

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
| Prompt injection | skillsafety | Override phrases in 11 languages (family+) |
| Homoglyphs | skillsafety | Mixed-script words (Latin+Cyrillic/Greek/Armenian) (family+) |
| Zero-width chars | skillsafety | Hidden Unicode characters in skill content (family+) |
| RTL override | skillsafety | Right-to-left text direction manipulation (family+) |
| Data exfil intent | skillsafety | Sensitive paths + external/webhook URLs correlation (family+) |
| Multi-language hiding | skillsafety | Unexpected script blocks in primary-language skills (family+) |

## Why HoneyBadger

| | HoneyBadger | Cisco MCP Scanner | Snyk agent-scan | Proximity |
|---|:-:|:-:|:-:|:-:|
| **Single binary** | Go | Python | Python | Python |
| **Offline mode** | yes | partial (static) | no | partial (local Ollama) |
| **MCP server mode** | yes (JSON-RPC) | scans MCP servers | scans MCP servers | scans MCP servers |
| **Paranoia levels** | 5 tiers | no | no | no |
| **SKILL.md scanning** | yes | no | yes | yes |
| **CVE scanning** | 8 lockfile formats | no | no | no |
| **Secrets detection** | gitleaks 800+ | Yara | yes (skills mode) | yes (skill scanning) |
| **Supply chain** | yes | no | no | no |
| **Attestation** | yes | no | no | no |
| **No cloud dependency** | yes | partial | no (needs Snyk API) | partial (Ollama ok) |
| **Runs on ARM/RPi** | yes | no | no | no |
| **Audit trail** | JSONL | no | no | no |

## Integrations

| Platform | Type | Guide |
|----------|------|-------|
| Claude Code | Skill + MCP + Hook | [docs/CLAUDE_CODE.md](docs/CLAUDE_CODE.md) |
| OpenAI Codex CLI | Hook | [docs/integrations/codex-cli.md](docs/integrations/codex-cli.md) |
| FamClaw | Built-in pipeline | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| OpenClaw | Skill | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| PicoClaw | Skill | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| NanoBot | Skill | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| CI/CD | CLI | [docs/EXAMPLES.md](docs/EXAMPLES.md) |
| MCP | JSON-RPC stdio | [docs/EXAMPLES.md](docs/EXAMPLES.md) |

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

Findings include rule metadata when available: `rule_id`, `more_info_url`, and `references` from the source YAML rule.
In text mode, the severity tag shows `[SEVERITY rule_id]` and a `→ url` line links to further documentation.

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
│   │   ├── stdin.go         # Stdin fetcher (piped input via -)
│   │   ├── stdin_test.go
│   │   └── tarball.go       # Tarball fetcher
│   ├── ignore/
│   │   ├── ignore.go        # .honeybadgerignore parser and finding filter
│   │   └── ignore_test.go
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
│   ├── INSTALLATION.md       # Installation guide for all runtimes
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

**v0.1.0 released** -- [download binaries](https://github.com/famclaw/honeybadger/releases/tag/v0.1.0)

All core scanners implemented and tested. Binaries signed with Sigstore cosign,
SPDX SBOMs attached to every release. Piped stdin input (`scan -`) and
`.honeybadgerignore` suppression are implemented (unreleased).

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Building

    make build              # current platform
    make cross              # all 5 targets (linux arm64/armv7/amd64, darwin arm64/amd64)
    make test               # run all tests
    make self-check         # scan ourselves at strict paranoia (requires prior release)
    make self-check-bootstrap  # scan at minimal paranoia (for initial releases only)
    make release-dry        # test GoReleaser locally (snapshot, no publish)

## Extending with custom rules

Detection rules are YAML files embedded in the binary. Add custom rules at
runtime by dropping `.yaml` files into `~/.honeybadger/rules/` (or set
`HONEYBADGER_RULES_DIR`):

    mkdir -p ~/.honeybadger/rules/custom
    cat > ~/.honeybadger/rules/custom/my-rule.yaml << 'EOF'
    id: my_custom_check
    kind: pattern
    scanner: supplychain
    category: custom
    severity: HIGH
    signal: file_content
    patterns:
      - regex: 'SOME_DANGEROUS_PATTERN'
        description: "My custom detection"
    message: "Custom rule matched"
    EOF
    honeybadger scan ./my-project  # custom rule will fire

See [rules/README.md](rules/README.md) for the full format spec.

## Release Checklist

1. `make self-check` passes at strict paranoia (or `self-check-bootstrap` for first release)
2. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
3. GoReleaser builds, signs, and publishes via `.github/workflows/release.yml`
4. Verify release: see [SECURITY.md](SECURITY.md#verifying-release-artifacts)
5. Set GitHub topics: `security`, `mcp`, `supply-chain`, `scanner`, `agentskills`, `golang`

## License

[MIT](./LICENSE)
