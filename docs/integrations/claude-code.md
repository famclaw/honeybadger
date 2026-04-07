# HoneyBadger + Claude Code: Pre-Install Hook

Block unsafe skills before they're installed. When a skill file changes,
HoneyBadger scans it and exits non-zero on FAIL, preventing installation.

For full Claude Code integration (skill registration, MCP server, project config),
see [../CLAUDE_CODE.md](../CLAUDE_CODE.md).

## Install HoneyBadger

```bash
# Go install
go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

# Or download binary
curl -fsSL https://github.com/famclaw/honeybadger/releases/latest/download/honeybadger-linux-amd64 \
  -o /usr/local/bin/honeybadger && chmod +x /usr/local/bin/honeybadger
```

## Set up the hook

### Step 1: Copy the hook script

```bash
mkdir -p .claude/hooks
cp examples/claude-code/scan-skill.sh .claude/hooks/scan-skill.sh
chmod +x .claude/hooks/scan-skill.sh
```

Or create `.claude/hooks/scan-skill.sh` manually:

```bash
#!/bin/bash
set -eo pipefail

input=$(cat)
file_path=$(echo "$input" | jq -r '.file_path // empty')

if [[ "$file_path" != *"/skills/"* ]] && [[ "$file_path" != *"SKILL.md"* ]]; then
    exit 0
fi

skill_dir=$(dirname "$file_path")

if ! command -v honeybadger &> /dev/null; then
    echo "WARNING: honeybadger not installed, skipping scan" >&2
    exit 0
fi

result=$(honeybadger scan "$skill_dir" --paranoia family --format ndjson --offline 2>/dev/null | tail -1)
verdict=$(echo "$result" | jq -r '.verdict // "FAIL"')

case "$verdict" in
    FAIL)
        echo "BLOCKED: HoneyBadger scan FAILED for $skill_dir" >&2
        echo "$result" | jq -r '.reasoning // "Security scan failed"' >&2
        exit 2
        ;;
    WARN)
        echo "WARNING: HoneyBadger found issues in $skill_dir" >&2
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
```

### Step 2: Register the hook

Add to `.claude/settings.json`:

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

## What happens

1. User drops a new skill file into `.claude/skills/`
2. Claude Code fires the `PreToolUse` hook
3. The hook runs `honeybadger scan` on the skill directory
4. **PASS**: skill installs normally
5. **WARN**: skill installs with a warning printed to stderr
6. **FAIL**: hook exits 2, Claude Code blocks the operation

## Troubleshooting

**Hook not firing**: Verify `.claude/settings.json` has the hook registered
and the script is executable (`chmod +x`).

**Timeout**: Large repos may take a few seconds. The hook uses `--offline`
mode which skips network calls. If still slow, try `--paranoia minimal`.

**False positives**: The supply chain scanner may flag patterns in documentation
(like security tool READMEs that discuss attack patterns). Use `--paranoia minimal`
to run only secrets + CVE scanners.

**Emergency bypass**: Remove the hook entry from `.claude/settings.json` temporarily.
Re-add it after the emergency.
