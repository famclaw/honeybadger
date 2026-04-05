# Using HoneyBadger with Claude Code

HoneyBadger integrates with Claude Code as an MCP server, giving Claude
the ability to security-scan repositories before you install skills,
tools, or MCP servers.

## Prerequisites

Install the honeybadger binary:

    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

Or download a prebuilt binary from
https://github.com/famclaw/honeybadger/releases and add it to your PATH.

## Setup: Project-Level (Recommended)

Add honeybadger as an MCP server in your project's `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "honeybadger",
      "args": ["--mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

This scopes honeybadger to the project. Claude Code will discover it via
the MCP `tools/list` handshake and can call `honeybadger_scan` during
conversations.

## Setup: User-Level (All Projects)

To make honeybadger available in every project, add it to your global
settings at `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "honeybadger",
      "args": ["--mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

## Usage

Once configured, Claude Code can call honeybadger during conversations.
Ask naturally:

- "Is github.com/someone/some-skill safe to install?"
- "Security scan this repo before I add it"
- "Vet github.com/someone/some-mcp at strict paranoia"
- "Check if this MCP server has any CVEs"

Claude will call the `honeybadger_scan` tool and interpret the results
for you, explaining any findings and recommending whether to proceed.

## MCP Tool: honeybadger_scan

Claude Code calls this tool with these parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `repo_url` | string | Yes | GitHub/GitLab URL or local path |
| `paranoia` | string | No | `minimal`, `family`, `strict`, `paranoid` (default: `family`) |
| `installed_sha` | string | No | SHA256 of installed version (for update detection) |
| `installed_tool_hash` | string | No | SHA256 of MCP tool definitions (rug-pull detection) |
| `path` | string | No | Subdirectory within repo to scan |

The tool returns a JSON result with verdict (PASS/WARN/FAIL), reasoning,
finding counts by severity, and scan metadata.

## Pre-Install Hook (Advanced)

You can configure a Claude Code hook that runs honeybadger before any
MCP server or skill installation. Add to `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__.*install.*",
        "command": "honeybadger scan \"$TOOL_INPUT\" --paranoia family --format text"
      }
    ]
  }
}
```

This runs a security scan whenever Claude attempts to use a tool matching
the install pattern, blocking if the scan fails.

## Environment Variables

Set these in your shell profile or `.env` file:

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | Higher API rate limits (60 -> 5000/hr) |
| `GITLAB_TOKEN` | GitLab private repo access |
| `HONEYBADGER_LLM` | LLM endpoint for AI-assisted verdict |
| `HONEYBADGER_LLM_KEY` | API key for LLM endpoint |
| `HONEYBADGER_LLM_MODEL` | Model name (e.g. `claude-sonnet-4-6`) |

These are passed to the honeybadger process via the `env` block in your
MCP config. They never appear in Claude's context window.

## Docker Alternative

If you prefer not to install the binary, use the Docker image:

```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "GITHUB_TOKEN",
        "ghcr.io/famclaw/honeybadger:latest",
        "--mcp-server"
      ],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

## Troubleshooting

**"honeybadger: command not found"** -- Ensure the binary is in your PATH.
Run `which honeybadger` to check. If using `go install`, verify that
`$GOPATH/bin` (usually `~/go/bin`) is in your PATH.

**MCP server not starting** -- Check Claude Code logs. The honeybadger
process must be able to start and speak JSON-RPC over stdio. Test
manually: `echo '{}' | honeybadger --mcp-server` should not crash.

**Rate limiting** -- Set `GITHUB_TOKEN` in the env block. Without it,
GitHub API is limited to 60 requests/hour.

**Timeouts on large repos** -- Large monorepos may take longer to scan.
The MCP server has no built-in timeout; Claude Code's default tool
timeout applies.
