# Changelog

## Unreleased

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
