# HoneyBadger

Standalone Go security scanner for auditing git repositories before installation.

## Status

**Wave 2 (Scanners) -- in progress.**

- Project skeleton with Go module, CLI entry point, types, helpers, and report interface
- CLI parses all flags and env vars; `scan` and `mcp-server` subcommands are stubs
- Scan types: Finding, ParanoiaLevel, Options, severity constants, block thresholds
- Helper functions ported from seccheck: WalkCode, IsPlaceholder, Redact, EditDistance, IsBinaryFile
- Report Emitter interface defined
- **Secrets scanner** using gitleaks v8 as in-process library (800+ credential patterns)
  - Noise reduction: skips placeholders, env var references, template variables
  - Severity mapping: AWS/private key/Stripe -> CRITICAL, others -> HIGH
  - Test file detection: reduces severity by one level for test/fixture paths
- **Supply chain scanner** with 16 regex patterns (curl-pipe-bash, reverse shell, crypto mining, webhook exfil, etc.) plus typosquat detection via edit distance
- **Dependency parser** supporting 8 lockfile formats: go.mod, package-lock.json, yarn.lock, requirements.txt, Pipfile.lock, Cargo.lock, Gemfile.lock, pom.xml
- **CVE scanner** querying osv.dev batch API with CVSS score mapping and fixed version extraction
- Makefile with build, cross-compile, test, and self-check targets
- All tests passing, go vet clean

## Project Structure

```
honeybadger/
├── cmd/honeybadger/
│   └── main.go              # CLI entry point
├── internal/
│   ├── fetch/
│   │   ├── fetch.go         # Repo type, Route(), Fetcher interface
│   │   ├── fetch_test.go
│   │   ├── github.go        # GitHub fetcher
│   │   ├── gitlab.go        # GitLab fetcher
│   │   └── tarball.go       # Tarball fetcher
│   ├── report/
│   │   └── types.go         # Emitter interface
│   └── scan/
│       ├── types.go          # Finding, ParanoiaLevel, Options, constants
│       ├── types_test.go     # Table-driven tests
│       ├── helpers.go        # WalkCode, IsPlaceholder, Redact, EditDistance, IsBinaryFile
│       ├── secrets.go        # Secrets scanner (gitleaks-powered)
│       ├── secrets_test.go   # Table-driven secrets scanner tests
│       ├── supplychain.go    # Supply chain risk pattern scanner + typosquat detection
│       ├── supplychain_test.go
│       ├── deps.go           # Dependency parser (8 lockfile formats)
│       ├── deps_test.go
│       ├── cve.go            # CVE scanner via osv.dev API
│       ├── cve_test.go
│       ├── meta.go           # SKILL.md meta scanner
│       ├── meta_test.go
│       ├── attestation.go    # Attestation verification scanner
│       └── attestation_test.go
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
