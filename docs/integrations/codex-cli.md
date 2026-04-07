# HoneyBadger + OpenAI Codex CLI: Pre-Install Hook

Block unsafe skills before installation in Codex CLI. Skills live in
`~/.codex/skills/`. The hook scans skill files on change and blocks on FAIL.

## Install HoneyBadger

```bash
go install github.com/famclaw/honeybadger/cmd/honeybadger@latest
```

## Set up the hook

### Step 1: Create the hook script

Save as `~/.codex/hooks/scan-skill.sh`:

```bash
#!/bin/bash
set -e

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
verdict=$(echo "$result" | jq -r '.verdict // "PASS"')

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

```bash
chmod +x ~/.codex/hooks/scan-skill.sh
```

### Step 2: Register the hook

Add to `~/.codex/config.json`:

```json
{
  "hooks": {
    "pre_install": {
      "command": "~/.codex/hooks/scan-skill.sh"
    }
  }
}
```

## Usage

```bash
# Codex CLI discovers honeybadger via the hook
codex skills install github.com/someone/some-skill
# → HoneyBadger scans automatically before installation
```
