## HoneyBadger Agent Instructions

**What this is**  
Go security scanner for AI agent skills and MCP servers. Scans for hardcoded secrets, CVEs, supply-chain risk, and build provenance before install. CLI + MCP server modes. MIT licensed.

**Code structure**  
- Scanners in `internal/scanner/`: secrets, supplychain, cve, meta, attestation  
- Core types in `internal/scan/`: `Finding`, `Options`, helpers  
- Engine in `internal/engine/`: scanner list, verdict logic  
- Entry points: `cmd/honeybadger/main.go` (CLI), `cmd/honeybadger/mcp.go` (MCP)

**Coding rules**  
- Go language only  
- Every scanner change requires matching test fixture  
- Fixtures must build secrets at runtime (not hardcoded) to avoid GitHub push protection  
- Run `make self-check` before submitting (HoneyBadger scans itself)

**Build & test**  
- `make build`  
- `make test`  
- `make self-check`  
- Integration tests: `go test -tags integration ./...`

**Module path**  
`github.com/famclaw/honeybadger`

## Codebase orientation

### Purpose

HoneyBadger is a Go security scanner that analyzes AI agent skills and MCP servers for hardcoded secrets, CVEs, supply-chain risks, and build provenance before installation. It performs static analysis only — it reads source code and metadata but never executes the scanned code.

### Runtime shape

The process starts with `cmd/honeybadger/main.go` parsing flags and routing to either CLI or MCP server mode. The scan pipeline runs in `internal/scan/scan.go` using concurrent `RunAll` with fan-in. Input is fetched via `internal/fetch` (GitHub, GitLab, stdin, tarball). Findings are emitted as NDJSON or text via `internal/report`. Configuration comes from flags, env vars, and `~/.honeybadger/rules/`. MCP server mode runs `honeybadger --mcp-server` and speaks JSON-RPC over stdio.

### Package map (internal/)

| Package | Responsibility | Key types / entry points | Depends on (other internal/) |
|---|---|---|---|
| engine | Verdict logic, tier/sandbox detection, scanner list builder | `BuildScannerList`, `ComputeVerdict` | scan, report |
| fetch | Repo routing and fetching | `Route`, `Fetcher`, `Repo` | — |
| ignore | .honeybadgerignore parser and suppression | `Parse`, `Set.Match` | scan |
| report | Output formatting (NDJSON, text, LLM) | `NewNDJSONEmitter`, `NewTextEmitter`, `CallLLM` | scan |
| scan | Core types, finding struct, severity constants | `Finding`, `ScanFunc`, `RunAll` | fetch |
| scanner | Individual scanners (8 total) | `Run` functions | scan, fetch, rules |
| store | Audit trail writer | `WriteAudit` | — |
| testfixture | In-memory repo builders for testing | `fixtures.go` | fetch |

### Scanners

| Scanner | What it detects | Rule source (YAML dir? code? both?) | Severity range |
|---|---|---|---|
| secrets | Hardcoded credentials (gitleaks v8) | YAML (800+ patterns) | High to Critical |
| cve | Known vulnerabilities in dependencies | osv.dev API (8 lockfile formats) | Low to Critical |
| supplychain | Remote script execution, typosquatting, reverse shells | YAML (patterns/dictionaries) | Low to High |
| meta | SKILL.md frontmatter validation | Code (YAML parsing) | Low to Medium |
| capability | Drift between declared permissions and code usage | Code (frontmatter vs source) | Medium to High |
| skillsafety | Prompt injection, Unicode obfuscation, data exfiltration intent | YAML (11 languages, 7 rule families) | Medium to High |
| mcptool | MCP tool injection, shadowing, capability mismatch, rug-pull | YAML (concealment, threat-framing, silent-redirect) | Medium to High |
| attestation | Build provenance, Cosign signatures, SHA256SUMS | Code (GitHub API, file checks) | Info to High |

### Entry points

| Binary | File | What it does |
|---|---|---|
| honeybadger | cmd/honeybadger/main.go | CLI entry point with scan, mcp-server, and flags |
| honeybadger | cmd/honeybadger/mcp.go | MCP server mode (JSON-RPC over stdio) |

### Rules (YAML)

Rules live in `rules/` at repo root (`rules/supplychain/`, `rules/skillsafety/`, `rules/mcptool/`). They load via `internal/rules/` with `Load(dir)` and merge embedded rules with `~/.honeybadger/rules/` (or `HONEYBADGER_RULES_DIR`). `.honeybadgerignore` suppresses findings by rule ID, glob, or SHA256.

### Configuration

Config loaded from CLI flags, env vars (`HONEYBADGER_LLM`, `GITHUB_TOKEN`), and `~/.honeybadger/rules/`. Paranoia tiers: `off`, `minimal`, `family`, `strict`, `paranoid`.

### Reports

`internal/report/` handles output formats: NDJSON (default), text, and LLM verdict via `CallLLM`. Findings include rule metadata (ID, URL, references). LLM verdict path uses `AssembleLLMPrompt` and `CallLLM` with JSON response parsing.

### Testing conventions

Tests live in each package's `_test.go` file. Golden files and `testdata/` dirs used. `internal/testfixture` provides in-memory repos for testing. `integration_test.go` handles CLI + MCP integration.

### "Where does X live?" — quick index

1. Where does a scan start? → `internal/scan` or `cmd/honeybadger/main.go`
2. Where is the CVE scanner? → `internal/scanner/cve/`
3. Where is the LLM verdict parsed? → `internal/report/llm.go`
4. Where are YAML rules stored? → `rules/`
5. Where is file-role classification? → `internal/scan/fileclass.go`
6. Where is the MCP server implemented? → `cmd/honeybadger/mcp.go`
7. Where is rule loading? → `internal/rules/`
8. Where are test fixtures? → `internal/testfixture/`
9. Where is the output emitter? → `internal/report/`
10. Where is suppression logic? → `internal/ignore/`
11. Where is the build provenance check? → `internal/scanner/attestation/`
12. Where is capability drift detected? → `internal/scanner/capability/`
13. Where is supply-chain risk analyzed? → `internal/scanner/supplychain/`
14. Where is the scan pipeline? → `internal/scan/scan.go`
15. Where is the runtime error handling? → `internal/scan/scan.go`

### Notable sharp edges

- File-role classification drops findings in test fixtures and rule corpus (not just test files)
- LLM verdict uses `--paranoia` level for context but only applies `high` threshold for `WARN` escalation in `strict`/`paranoid` mode
- MCP-server mode optionally accepts `--rules-dir` via CLI, else falls back to `HONEYBADGER_RULES_DIR` / default
- YAML rule loading is the sole code path — hardcoded Go patterns were removed in v0.3.0
- `RunAll` returns a channel of `Event` (Finding or RuntimeError) for concurrent fan-in
- `isBinaryContent` skips binary files using null-byte detection
- `CheckToolHash` uses regex to extract tool names from source code
- `ComputeVerdict` drops `INFO` findings entirely and escalates `WARN` to `FAIL` in `strict`/`paranoid` tiers
- `parseGitHubURL` handles `git@github.com:` style URLs and strips `.git` suffix
- `buildSourceBlock` prioritizes dependency files, build scripts, and files with findings
- `extractDependencyNames` parses `package.json` and `requirements.txt` for typosquatting
- `detectShadowing` uses the injection hit set from `detectInjectionWithHits` for cross-tool analysis
