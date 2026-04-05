# Installing HoneyBadger in Claw Runtimes

## Quick Start

    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest
    honeybadger scan github.com/someone/some-skill

## Binary Installation

### From source (all platforms)
    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

### From GitHub Releases
Download the prebuilt binary for your platform from
https://github.com/famclaw/honeybadger/releases

Available targets:
- `honeybadger-linux-arm64` -- Raspberry Pi 4/5
- `honeybadger-linux-armv7` -- Raspberry Pi 3
- `honeybadger-linux-amd64` -- Linux x86_64
- `honeybadger-darwin-arm64` -- macOS Apple Silicon
- `honeybadger-darwin-amd64` -- macOS Intel

### Docker
    docker pull ghcr.io/famclaw/honeybadger:latest
    docker run --rm ghcr.io/famclaw/honeybadger scan github.com/someone/some-skill

Multi-arch image available for `linux/amd64` and `linux/arm64`.

### Android / Termux
    pkg install golang
    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

Note: Sandbox unavailable on Termux. Effective paranoia capped at `family`.

## Verifying Downloads

All release binaries are signed with Sigstore cosign (keyless). Verify before use:

    cosign verify-blob honeybadger-linux-arm64 \
      --bundle honeybadger-linux-arm64.bundle \
      --certificate-identity-regexp=".*famclaw/honeybadger.*" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

    gh attestation verify honeybadger-linux-arm64 --repo famclaw/honeybadger

## MCP Server Mode

HoneyBadger runs as an MCP server over stdio, exposing the `honeybadger_scan` tool.
Any MCP-compatible runtime can call it.

    honeybadger --mcp-server

## Integration: FamClaw

FamClaw discovers MCP tools automatically via the `tools/list` handshake.
Add honeybadger to your `config.yaml`:

```yaml
skills:
  auto_seccheck: true
  block_on_fail: true

  mcp_servers:
    honeybadger:
      transport: stdio
      command: honeybadger
      args: ["--mcp-server"]

  credentials:
    honeybadger:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

Credentials are injected as environment variables when the MCP server process
is spawned. They never appear in LLM context.

**How it works in FamClaw:**
1. A family member asks to install a skill or vet a repo
2. FamClaw's policy engine evaluates the request (parent approval may be required)
3. If allowed, the agent calls `honeybadger_scan` via MCP
4. HoneyBadger fetches the repo, runs all scanners, returns PASS/WARN/FAIL
5. FamClaw blocks installation if verdict is FAIL

**Remote mode** (for constrained devices like Android):
```yaml
skills:
  mcp_servers:
    honeybadger:
      transport: http
      url: "http://192.168.1.10:8090/mcp"
      headers:
        Authorization: "Bearer ${MCP_TOKEN}"
```

Run honeybadger on a LAN server and point constrained devices to it.

## Integration: OpenClaw

In your OpenClaw MCP config:
```yaml
mcp_servers:
  honeybadger:
    command: honeybadger
    args: ["--mcp-server"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

## Integration: PicoClaw

In PicoClaw's tool configuration:
```yaml
tools:
  - name: honeybadger
    type: mcp
    command: honeybadger --mcp-server
```

## Integration: Claude Code

See [CLAUDE_CODE.md](CLAUDE_CODE.md) for full Claude Code setup instructions.

Quick setup -- add to your project's `.claude/settings.local.json`:
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

## SKILL.md Registration

HoneyBadger ships with a SKILL.md at the repo root. When installed via skillbridge,
the runtime auto-discovers it. Triggers include:
- "honeybadger"
- "scan this repo"
- "is this safe to install"
- "check this skill"
- "vet this"
- "security scan"
- "verify this update"
- "check for updates"

## Paranoia Levels

| Level | Scanners | LLM | Blocks on |
|-------|----------|-----|-----------|
| `off` | None | No | Nothing |
| `minimal` | secrets, cve | No | CRITICAL |
| `family` | secrets, cve, supplychain, meta | Yes | HIGH+ |
| `strict` | all + attestation | Yes | MEDIUM+ (WARN=FAIL) |
| `paranoid` | all + allowlist | Yes | LOW+ |

The CLI accepts all five levels. The MCP tool accepts `minimal`, `family`,
`strict`, and `paranoid` (defaults to `family`).

Set globally in your runtime config or per-scan via the MCP tool parameter.

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `GITHUB_TOKEN` | Higher GitHub API rate limits (60 -> 5000/hr) | No |
| `GITLAB_TOKEN` | GitLab private repo access | No |
| `HONEYBADGER_LLM` | LLM endpoint for verdict analysis | No |
| `HONEYBADGER_LLM_KEY` | API key for LLM endpoint | No |
| `HONEYBADGER_LLM_MODEL` | Model name for LLM | No |

## Troubleshooting

**"routing: unsupported URL"** -- URL format not recognized. Use `github.com/owner/repo`, `gitlab.com/group/project`, or a local filesystem path.

**Rate limiting (GitHub)** -- Set `GITHUB_TOKEN` for 5000 req/hr instead of 60.

**Offline mode** -- Use `--offline` flag on the CLI for air-gapped environments. The MCP tool does not expose an offline parameter.

**Binary not found** -- Ensure honeybadger is in your PATH, or use the absolute path in your runtime config.

**Termux sandbox warning** -- Expected. Sandbox is unavailable on Android. Paranoia is capped at `family`.

**Docker permission denied** -- Run `docker run --rm ghcr.io/famclaw/honeybadger ...` without volume mounts. HoneyBadger fetches repos over the network inside the container.
