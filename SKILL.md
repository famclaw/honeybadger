---
name: honeybadger
version: "1.0.0"
description: >
  Scan a GitHub or GitLab repository for security issues before installing it
  as a skill, tool, or MCP server. Use when the user wants to check, vet,
  scan, or review a repository for safety before installation. Detects
  hardcoded secrets, known CVEs, supply chain risks, and build provenance.
author: famclaw
license: AGPL-3.0-only
tags:
  - security
  - scanner
  - supply-chain
  - mcp
metadata: {
  "openclaw": {
    "emoji": "🦡",
    "requires": { "bins": ["honeybadger"] },
    "install": [
      {
        "id": "go-install",
        "kind": "shell",
        "command": "go install github.com/famclaw/honeybadger/cmd/honeybadger@latest",
        "bins": ["honeybadger"],
        "label": "Install HoneyBadger (requires Go)"
      }
    ]
  }
}
---

# HoneyBadger

HoneyBadger is a security scanner for software plugins. Before anything gets
installed on your family server or development machine, HoneyBadger checks it.

**HoneyBadger don't care. HoneyBadger checks anyway.**

## When to use this skill

Use this skill when the user:
- Wants to install a skill, MCP server, or tool from a GitHub or GitLab repo
- Asks "is this safe to install?", "can you check this?", "vet this repo"
- Wants to verify an update to an already-installed skill
- Asks about the security of any GitHub or GitLab repository

## Prerequisites

The `honeybadger` binary must be in PATH. If not installed:

```bash
go install github.com/famclaw/honeybadger/cmd/honeybadger@latest
```

## How to invoke

Basic scan (default: family paranoia level):
```bash
honeybadger scan <repo-url> --format text
```

With specific paranoia level:
```bash
honeybadger scan <repo-url> --paranoia minimal|family|strict|paranoid --format text
```

For update verification (rug-pull detection):
```bash
honeybadger scan <repo-url> --installed-sha <sha256-of-installed-archive>
```

## Paranoia levels

- **minimal** — secrets + CVEs only. Fast. No LLM. Blocks on CRITICAL.
- **family** — full scan + LLM verdict. Default. Blocks on HIGH+.
- **strict** — adds attestation + build provenance. WARN treated as FAIL.
- **paranoid** — strict + allowlist enforcement. Blocks on LOW+.

## How to interpret output

Exit codes: 0=PASS, 1=WARN, 2=FAIL, 3=scan error

With `--format text`: human-readable summary.
With `--format ndjson`: one JSON event per line. The final line
(`"type":"result"`) contains the verdict and reasoning.

Always show the verdict and reasoning to the user.
If verdict is WARN or FAIL, quote the `key_finding` field.
If verdict is FAIL, tell the user not to install.

## Example

User: "Is github.com/some-user/some-skill safe to install?"

```bash
honeybadger scan github.com/some-user/some-skill --format text
```

Report the verdict and reasoning to the user in plain language.
