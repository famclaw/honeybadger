# HoneyBadger — Claude Code Integration Guide

HoneyBadger scans GitHub and GitLab repositories for security issues.
Integrate it with Claude Code as a skill, MCP server, or both.

## Prerequisites

```bash
go install github.com/famclaw/honeybadger/cmd/honeybadger@latest
honeybadger --version
```

## Option 1: Install as a Claude Code skill (recommended)

Skills auto-trigger when Claude matches the task to the skill description.
Install the skill and Claude will invoke HoneyBadger automatically when you
ask it to check a repository.

```bash
mkdir -p ~/.claude/skills/honeybadger
curl -fsSL \
  https://raw.githubusercontent.com/famclaw/honeybadger/main/SKILL.md \
  -o ~/.claude/skills/honeybadger/SKILL.md
```

Usage — ask naturally in Claude Code:

```
You: Is github.com/some-user/some-skill safe to install?
Claude: [runs honeybadger scan, reports findings and verdict]

You: Vet this before I add it as an MCP server
Claude: [asks for URL if not provided, then scans]
```

Explicit invocation via slash command:
```
/honeybadger github.com/some-user/some-skill
```

## Option 2: Register as an MCP server

Use this when you want HoneyBadger available as a programmatic tool across
multiple projects:

```bash
claude mcp add honeybadger honeybadger --mcp-server
```

Verify registration:
```bash
claude mcp list
# honeybadger should appear
```

The `honeybadger_scan` MCP tool accepts:
- `repo_url` (required)
- `paranoia` (optional: minimal/family/strict/paranoid, default: family)
- `installed_sha` (optional: SHA256 of installed version, for update checks)
- `installed_tool_hash` (optional: SHA256 of tool defs, for rug-pull detection)
- `path` (optional: subdirectory for monorepos)

## Option 3: Skill + MCP server

Install both for natural language triggering plus programmatic tool access:

```bash
# Skill
mkdir -p ~/.claude/skills/honeybadger
curl -fsSL \
  https://raw.githubusercontent.com/famclaw/honeybadger/main/SKILL.md \
  -o ~/.claude/skills/honeybadger/SKILL.md

# MCP server
claude mcp add honeybadger honeybadger --mcp-server
```

## Option 4: Project-scoped skill

Scope HoneyBadger to a specific project:

```bash
# In your project root
mkdir -p .claude/skills/honeybadger
curl -fsSL \
  https://raw.githubusercontent.com/famclaw/honeybadger/main/SKILL.md \
  -o .claude/skills/honeybadger/SKILL.md
```

Claude Code automatically loads `.claude/skills/` from directories added
with `--add-dir`, without requiring additional environment variables.

## Project-scoped MCP config

Configure HoneyBadger per-project in `.mcp.json`:

```json
{
  "mcpServers": {
    "honeybadger": {
      "type": "stdio",
      "command": "honeybadger",
      "args": ["--mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}",
        "HONEYBADGER_LLM": "http://localhost:11434/v1"
      }
    }
  }
}
```

## Pre-install hook

Automatically scan repos before Claude installs them:

```bash
# .claude/hooks/pre-install-scan.sh
#!/bin/bash
REPO_URL="$1"
if [ -z "$REPO_URL" ]; then exit 0; fi

result=$(honeybadger scan "$REPO_URL" --paranoia family --format ndjson 2>/dev/null | \
  grep '"type":"result"' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verdict']+'|'+d.get('reasoning',''))")

verdict=$(echo "$result" | cut -d'|' -f1)
reasoning=$(echo "$result" | cut -d'|' -f2-)

if [ "$verdict" = "FAIL" ]; then
  echo "BLOCKED: HoneyBadger scan FAILED"
  echo "Reason: $reasoning"
  exit 1
fi
```

Register in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": ".claude/hooks/pre-install-scan.sh" }]
      }
    ]
  }
}
```

## Environment variables

```bash
# Higher GitHub API rate limit (60 → 5000 req/hour)
export GITHUB_TOKEN=your_token_here

# LLM endpoint for security analysis
export HONEYBADGER_LLM=http://localhost:11434/v1
export HONEYBADGER_LLM_KEY=your_api_key   # omit for local Ollama
export HONEYBADGER_LLM_MODEL=llama3.1:8b
```

## Verify the release binary

```bash
cosign verify-blob honeybadger \
  --bundle honeybadger.bundle \
  --certificate-identity-regexp ".*famclaw/honeybadger.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

curl -fsSL \
  https://github.com/famclaw/honeybadger/releases/latest/download/SHA256SUMS | \
  grep honeybadger-linux-amd64 | sha256sum --check
```
