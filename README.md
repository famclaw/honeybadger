# HoneyBadger

Standalone Go security scanner for auditing git repositories before installation.

## Status

**Wave 4 (CLI Wiring + Store) -- complete.**

- Project skeleton with Go module, CLI entry point, types, helpers, and report interface
- **Full CLI pipeline** wired end-to-end in `cmd/honeybadger/main.go`:
  - Paranoia level parsing and validation
  - `--force` flag bypasses scan with PASS result
  - Tier detection (online/offline) via GitHub API HEAD + DNS fallback
  - Sandbox detection (Docker, macOS sandbox-exec, Termux) with effective paranoia capping
  - Emitter selection (NDJSON or text) based on `--format` flag
  - Repository fetching via `fetch.Route()` with token and subpath support
  - Scanner execution via `scan.RunAll()` with streaming finding emission
  - Health event emission from repo metadata
  - LLM verdict integration (when paranoia >= family and endpoint configured)
  - Rules-based verdict computation with paranoia-aware thresholds, strict/paranoid WARN-to-FAIL escalation, and LLM verdict merging (worst verdict wins)
  - Finding counts, CVE aggregation, and full result event emission
  - Exit codes: PASS=0, WARN=1, FAIL=2, unknown=3
  - `--installed-sha` update verification (SHA256 of repo content)
  - `--installed-tool-hash` verification (detects mcp-go tool registration changes)
  - `--db` audit trail (appends JSON result to file)
- **Audit store** (`internal/store/audit.go`) — lightweight JSONL file append for scan results
- Scan types: Finding, ParanoiaLevel, Options, severity constants, block thresholds
- Helper functions: WalkCode, IsPlaceholder, Redact, EditDistance, IsBinaryFile
- Report Emitter interface defined
- **Secrets scanner** using gitleaks v8 as in-process library (800+ credential patterns)
- **Supply chain scanner** with 16 regex patterns plus typosquat detection
- **Dependency parser** supporting 8 lockfile formats
- **CVE scanner** querying osv.dev batch API
- **Meta scanner** for SKILL.md metadata analysis
- **Attestation scanner** for verification of signed artifacts
- **Concurrent scan runner** with fan-in architecture, paranoia-gated scanner selection, panic recovery
- **NDJSON reporter** — streaming newline-delimited JSON emitter, thread-safe
- **Text reporter** — human-readable output with severity markers, verdict block formatting
- **LLM integration** — prompt assembly with 32K token budget, OpenAI-compatible API calling
- Makefile with build, cross-compile, test, and self-check targets
- All tests passing, go vet clean

## Project Structure

```
honeybadger/
├── cmd/honeybadger/
│   ├── main.go              # CLI entry point — full pipeline wiring
│   └── main_test.go         # Table-driven tests for verdict, exit codes, tool hash
├── internal/
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
│   │   ├── types.go          # Finding, ParanoiaLevel, Options, constants
│   │   ├── types_test.go     # Table-driven tests
│   │   ├── helpers.go        # WalkCode, IsPlaceholder, Redact, EditDistance, IsBinaryFile
│   │   ├── secrets.go        # Secrets scanner (gitleaks-powered)
│   │   ├── secrets_test.go
│   │   ├── supplychain.go    # Supply chain risk pattern scanner + typosquat detection
│   │   ├── supplychain_test.go
│   │   ├── deps.go           # Dependency parser (8 lockfile formats)
│   │   ├── deps_test.go
│   │   ├── cve.go            # CVE scanner via osv.dev API
│   │   ├── cve_test.go
│   │   ├── meta.go           # SKILL.md meta scanner
│   │   ├── meta_test.go
│   │   ├── attestation.go    # Attestation verification scanner
│   │   ├── attestation_test.go
│   │   ├── runner.go          # Concurrent scan runner with fan-in
│   │   └── runner_test.go
│   └── store/
│       ├── audit.go           # JSONL audit trail writer
│       └── audit_test.go
├── .gitignore
├── go.mod
├── Makefile
└── README.md
```

## Build

```bash
make build        # build for current platform
make cross        # cross-compile all targets
make test         # run all tests
```
