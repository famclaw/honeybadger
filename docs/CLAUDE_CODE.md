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

```text
You: Is github.com/some-user/some-skill safe to install?
Claude: [runs honeybadger scan, reports findings and verdict]

You: Vet this before I add it as an MCP server
Claude: [asks for URL if not provided, then scans]
```

Explicit invocation via slash command:
```text
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

Automatically scan skill files before Claude installs them.
Create `.claude/hooks/scan-skill.sh`:

```bash
#!/bin/bash
# HoneyBadger pre-install skill scanner for Claude Code
# Blocks skills that fail security scanning.

set -eo pipefail

input=$(cat)
file_path=$(echo "$input" | jq -r '.file_path // empty')

# Only fire on skill file changes
if [[ "$file_path" != *"/skills/"* ]] && [[ "$file_path" != *"SKILL.md"* ]]; then
    exit 0
fi

# Get the directory containing the skill
skill_dir=$(dirname "$file_path")

# Run HoneyBadger on the skill directory
if ! command -v honeybadger &> /dev/null; then
    echo "WARNING: honeybadger not installed, skipping scan" >&2
    exit 0
fi

# Capture scanner output AND its pipeline status in a guarded assignment so a
# non-zero scan exit reaches the verdict logic instead of aborting the hook
# under `set -e` before we can classify the result.
scan_status=0
result=$(honeybadger scan "$skill_dir" --paranoia family --format ndjson --offline 2>/dev/null | tail -1) || scan_status=$?

# Parse the verdict defensively: malformed or empty output yields an empty verdict.
verdict=$(printf '%s' "$result" | jq -r '.verdict // empty' 2>/dev/null) || true

case "$verdict" in
    PASS)
        if [ "$scan_status" -ne 0 ]; then
            echo "BLOCKED: HoneyBadger returned PASS but exited $scan_status for $skill_dir" >&2
            exit 2
        fi
        exit 0
        ;;
    WARN)
        if [ "$scan_status" -ne 1 ]; then
            echo "BLOCKED: HoneyBadger returned WARN but exited $scan_status for $skill_dir" >&2
            exit 2
        fi
        echo "WARNING: HoneyBadger found issues in $skill_dir" >&2
        echo "$result" | jq -r '.reasoning // "Security warnings found"' >&2
        exit 0  # Allow with warning. Change to exit 2 to block.
        ;;
    FAIL)
        if [ "$scan_status" -ne 2 ]; then
            echo "BLOCKED: HoneyBadger returned FAIL but exited $scan_status for $skill_dir" >&2
            exit 2
        fi
        echo "BLOCKED: HoneyBadger scan FAILED for $skill_dir" >&2
        echo "$result" | jq -r '.reasoning // "Security scan failed"' >&2
        exit 2  # Claude Code hook convention: exit 2 = block
        ;;
    *)
        echo "BLOCKED: HoneyBadger returned a malformed or empty verdict for $skill_dir" >&2
        exit 2
        ;;
esac
```

Register in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": ".claude/hooks/scan-skill.sh" }]
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
