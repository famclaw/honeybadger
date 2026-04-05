---
name: honeybadger
version: "1.0.0"
description: >
  Security scanner for skills, tools, and MCP servers.
  HoneyBadger don't care. HoneyBadger checks anyway.
author: famclaw
license: AGPL-3.0-only
tags: [security, scanner, supply-chain, mcp]
platforms: [linux, darwin, android]

triggers:
  - "honeybadger"
  - "scan this repo"
  - "is this safe to install"
  - "check this skill"
  - "vet this"
  - "security scan"
  - "verify this update"
  - "check for updates"

requires:
  bins_optional:
    linux-arm64:  bin/honeybadger-linux-arm64
    linux-armv7:  bin/honeybadger-linux-armv7
    linux-amd64:  bin/honeybadger-linux-amd64
    darwin-arm64: bin/honeybadger-darwin-arm64
    darwin-amd64: bin/honeybadger-darwin-amd64
  env_optional:
    GITHUB_TOKEN: "Higher GitHub API rate limits (60 -> 5000 req/hour)"
    GITLAB_TOKEN: "GitLab API access for private repos"
    HONEYBADGER_LLM: "Override LLM endpoint for security analysis"

invoke: "honeybadger scan {repo_url} --paranoia {paranoia} --format ndjson"

chrome_devtools_mcp:
  preferred: true
  fallback: api_mode
---

# HoneyBadger

HoneyBadger is a security scanner for software plugins about to be installed
on your family server. Before you install anything, HoneyBadger checks it.

**HoneyBadger don't care. HoneyBadger checks anyway.**

## Usage

> "Honeybadger github.com/someone/some-skill"
> "Is this safe to install? github.com/someone/some-mcp"
> "Vet this before I install it"
> "Check if my installed skills have updates"

## What it checks

- Hardcoded secrets and API keys (800+ patterns via gitleaks)
- Supply chain risks: scripts that download and execute remote code
- Known CVEs in all dependencies (Go, npm, PyPI, Rust, Ruby, Maven)
- Build provenance and attestation verification
- SKILL.md declared permissions vs actual code behavior
- Repo health: age, contributors, recent ownership changes, license
- MCP tool definition changes between versions (rug-pull detection)

## Paranoia levels

Configure in your claw runtime's config.yaml:

- **minimal** -- CVE + secrets only. Fast. No LLM.
- **family** -- Full scan + LLM verdict. Default.
- **strict** -- Adds attestation + govulncheck. WARN = FAIL.
- **paranoid** -- Strict + allowlist. Rejects unsigned binaries.

## Android / Termux

HoneyBadger compiles and runs on Android via Termux:

    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

Sandbox unavailable on Android. Effective paranoia capped at family.
Attestation checks skipped (cosign not available). Both noted in report.
