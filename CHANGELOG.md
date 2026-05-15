# Changelog

## v0.5.0 -- 2026-05-15

### Added
- `mcptool` scanner (8th scanner): analyzes MCP tool definitions for prompt
  injection, Unicode obfuscation, cross-tool shadowing, capability mismatch,
  and rug-pull drift. Fed by a caller-supplied `--tool-manifest` (MCP
  `tools/list` JSON) or, when absent, best-effort source extraction.
- `--tool-manifest` and `--tool-baseline` CLI flags.
- `mcp-no-tools-found` finding -- an MCP server whose tools cannot be analyzed
  no longer passes silently.
- `rules/mcptool/` YAML rule directory (concealment / threat-framing /
  silent-redirect prompt-injection patterns).

## v0.4.0 -- 2026-05-15

### Added
- `capability` scanner: detects drift between `requires.{network,filesystem,bins,env_optional}` declared in `SKILL.md` frontmatter and the actual code. Active contradictions (declared:false but used) are SevHigh; undeclared usage is SevMedium. Runs at family/strict/paranoid paranoia. Per-file findings with `cap-*-drift` RuleIDs; skips `_test.go` / `testdata/` / `testfixture/`.

### Changed
- `Options.Rules` is now `*rules.RuleSet` (was `interface{}`). Compile-time type safety replaces runtime assertions; the misleading "import cycle" comment is removed.
- Scanner runtime errors (panics, external-tool failures) are now `RuntimeError` events distinct from security findings. A panicking scanner no longer flips a clean repo to FAIL.
- `RunAll` returns `<-chan scan.Event` (a sealed union of `Finding` and `RuntimeError`) instead of `<-chan Finding`.
- `ScanFunc` signature gains a `chan<- RuntimeError` parameter for reporting scanner-internal failures.
- `run()` parameters extracted into a `runConfig` struct (was 16 positional parameters).
- Scan events (`SandboxEvent`, `HealthEvent`, `ResultEvent`, `ResultEarlyEvent`, `SuppressionEvent`, `ProgressEvent`) are typed structs in `internal/engine/events.go` instead of `map[string]any` literals.
- `TextEmitter.Emit` is now atomic — multi-line findings can no longer be interleaved by concurrent emitters.
- `DetectSandbox` on macOS verifies `sandbox-exec` via `exec.LookPath` instead of assuming presence.
- `meta.parseFrontmatter` exported as `meta.ParseFrontmatter` for reuse by the `capability` scanner.
- `meta` scanner narrowed to frontmatter validation only. Network / filesystem / exec drift detection moved into the new `capability` scanner.

### Fixed
- `Emit()` errors in the CLI are now handled — a broken pipe no longer produces empty output with exit code 0.
- `WriteAudit` calls `f.Sync()` so audit data reaches disk before the function returns.
- `interface{}` replaced with `any` in `internal/fetch/github.go`.
- `fmt.Sprintf("%x", …)` replaced with `hex.EncodeToString` in `ComputeRepoHash` and `CheckToolHash`.

### Removed
- `SevError` severity. Scanner runtime errors are now `RuntimeError` events.

## v0.3.0 -- 2026-04-08

### Added
- `.honeybadgerignore` file support for suppressing findings by rule ID, glob, or SHA256
- Piped input via `honeybadger scan -` (treats stdin as SKILL.md, 10 MB cap)
- New NDJSON event type `suppression_summary`

### Changed
- Detection rules migrated from Go to YAML. All skillsafety and supplychain patterns are now defined in `rules/*.yaml` files embedded at build time. Zero behavior change for existing users.

### Added
- Runtime rule extension -- drop YAML files into `~/.honeybadger/rules/` (or set `HONEYBADGER_RULES_DIR`) to add custom detection rules without rebuilding the binary.
- `--rules-dir <path>` CLI flag to override the user rules directory.
- `rules/README.md` -- format spec and contribution guide for YAML detection rules.
- Rule metadata propagation: findings now carry `rule_id`, `more_info_url`, and `references` from their source YAML rule. Text output shows `[SEVERITY rule_id]` and a `→ url` line when metadata is present. LLM prompt references rule IDs in reasoning.

### Fixed
- Rule loading is now the sole code path -- hardcoded Go fallbacks deleted
- Dictionary rule metadata (severity, message) now flows to typosquat findings
- `--rules-dir` flag now works in MCP server mode (flag > env var > default)

### Removed
- Hardcoded pattern globals (`overridePatterns`, `sensitivePathPatterns`, `webhookDomains`, `popularPackages`, `supplyChainPatterns`, `compiledPatterns`)

### Notes
- Correlation rules (rules that combine multiple signals) remain in Go code. Pattern and dictionary rules live in YAML. See `rules/README.md` for details.

## v0.2.1 -- 2026-04-07

### Added
- Multi-language prompt injection detection: Chinese, Russian, Spanish, French, German, Japanese, Korean, Arabic, Portuguese, Italian (10 new languages, 11 total)
- Homoglyph detection -- flags words mixing Latin/Cyrillic/Greek/Armenian scripts within a single word

### Fixed
- Skillsafety scanner no longer misses non-English instruction smuggling

## v0.2.0 -- 2026-04-07

### Added
- Skillsafety scanner: prompt injection, Unicode obfuscation, data exfiltration intent, multi-language hiding
- Typosquat dictionary expanded to 53 packages
- Integration docs: Claude Code hook guide, Codex CLI hook guide
- Integrations table in README

## v0.1.0 -- 2026-04-06

First release. 5 cross-compiled binaries (linux amd64/arm64/armv7, darwin
amd64/arm64) with cosign signatures, SPDX SBOMs, and build attestation.

### Scanners
- **Secrets** -- gitleaks v8, 800+ credential patterns with noise reduction
- **Supply chain** -- curl|bash, eval, reverse shell, crypto mining, typosquatting detection
- **CVE** -- osv.dev batch API across Go, npm, PyPI, Rust, Ruby, Maven (8 lockfile formats)
- **SKILL.md meta** -- declared vs actual permissions mismatch
- **Attestation** -- build provenance, cosign verification, SHA256SUMS (strict/paranoid only)

### Features
- CLI: `honeybadger scan <url>` with 5 paranoia levels (off/minimal/family/strict/paranoid)
- MCP server mode: `honeybadger --mcp-server` (JSON-RPC over stdio)
- NDJSON and human-readable text output
- LLM-assisted verdict (optional, any OpenAI-compatible endpoint)
- JSONL audit trail
- Fetch: GitHub API, GitLab API, tarball, local directory
- Offline mode: `--offline` for air-gapped environments
- LLM timeout: `--llm-timeout` flag and `HONEYBADGER_LLM_TIMEOUT` env var

### CI/CD
- govulncheck, CodeQL, dependabot
- GoReleaser with self-check gate (HoneyBadger scans itself before release)
- Cosign keyless signing (Sigstore), SPDX SBOMs via syft
- Build attestation via GitHub Actions

### Docs
- `docs/INSTALLATION.md` -- installation guide for FamClaw, OpenClaw, PicoClaw, NanoBot
- `docs/EXAMPLES.md` -- CLI and MCP usage examples, NDJSON event format
- `SKILL.md` -- AgentSkills manifest for skill registries
- `SECURITY.md` -- vulnerability reporting and binary verification

### Known issues
- armv7 SBOM named `arm` instead of `armv7` (fixed in code, will ship in v0.1.1)
