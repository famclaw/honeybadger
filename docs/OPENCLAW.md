# HoneyBadger — OpenClaw Integration Guide

HoneyBadger scans GitHub and GitLab repositories for security issues before
you install them as OpenClaw skills or MCP servers.

## Prerequisites

```bash
# Install HoneyBadger binary (requires Go 1.22+)
go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

# Verify
honeybadger --version
```

## Install as an OpenClaw skill

### Option 1: Workspace skills directory (recommended)

```bash
mkdir -p ~/.openclaw/workspace/skills/honeybadger
curl -fsSL \
  https://raw.githubusercontent.com/famclaw/honeybadger/main/SKILL.md \
  -o ~/.openclaw/workspace/skills/honeybadger/SKILL.md
```

### Option 2: Personal skills directory (applies across workspaces)

```bash
mkdir -p ~/.agents/skills/honeybadger
curl -fsSL \
  https://raw.githubusercontent.com/famclaw/honeybadger/main/SKILL.md \
  -o ~/.agents/skills/honeybadger/SKILL.md
```

### Verify skill is loaded

```bash
# List eligible skills — honeybadger should appear
openclaw skills list --eligible

# Get skill details
openclaw skills info honeybadger
```

If `honeybadger` does not appear:
1. Check binary is in PATH: `which honeybadger`
2. Check SKILL.md is in the correct directory
3. Restart the OpenClaw gateway

## Usage

In any OpenClaw chat (Telegram, WhatsApp, Discord, Web UI, FamClaw):

```
You: Is github.com/some-user/some-skill safe to install?
Agent: [runs honeybadger scan, reports verdict and findings]

You: Vet this before I install it: github.com/some-user/some-mcp
Agent: [runs honeybadger scan with family paranoia, reports results]

You: Check for updates to my installed skills
Agent: [runs honeybadger with --installed-sha for each installed skill]
```

## Usage with FamClaw

FamClaw calls HoneyBadger automatically before installing skills:

```bash
famclaw skill install github.com/some-user/some-skill
```

Manual scan from any FamClaw gateway:

```
"Honeybadger github.com/some-user/some-skill"
```

## Usage with Docker sandbox

If your OpenClaw agent runs in a Docker sandbox, install HoneyBadger inside
the container via `agents.defaults.sandbox.docker.setupCommand`:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "non-main",
        "docker": {
          "setupCommand": "apt-get install -y golang-go && go install github.com/famclaw/honeybadger/cmd/honeybadger@latest"
        }
      }
    }
  }
}
```

Or use a custom image with HoneyBadger pre-installed:

```dockerfile
FROM golang:1.26-alpine AS builder
RUN go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

FROM ubuntu:24.04
COPY --from=builder /root/go/bin/honeybadger /usr/local/bin/
```

## Configuration

Set these environment variables to improve scan quality:

```bash
# Higher GitHub API rate limit (60 → 5000 req/hour)
export GITHUB_TOKEN=your_token_here

# Use a specific LLM endpoint for security analysis
export HONEYBADGER_LLM=http://localhost:11434/v1
```

To inject environment variables for the skill in OpenClaw config:

```json
{
  "skills": {
    "entries": {
      "honeybadger": {
        "env": {
          "GITHUB_TOKEN": "your_token_here"
        }
      }
    }
  }
}
```

## Verify the release binary

Release binaries are signed with cosign (keyless, Sigstore). Verify before
using any downloaded binary:

```bash
# Download binary and signature bundle
curl -fsSL \
  https://github.com/famclaw/honeybadger/releases/latest/download/honeybadger-linux-amd64 \
  -o honeybadger
curl -fsSL \
  https://github.com/famclaw/honeybadger/releases/latest/download/honeybadger-linux-amd64.bundle \
  -o honeybadger.bundle

# Verify cosign signature
cosign verify-blob honeybadger \
  --bundle honeybadger.bundle \
  --certificate-identity-regexp ".*famclaw/honeybadger.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify SHA256
curl -fsSL \
  https://github.com/famclaw/honeybadger/releases/latest/download/SHA256SUMS | \
  grep honeybadger-linux-amd64 | sha256sum --check
```
