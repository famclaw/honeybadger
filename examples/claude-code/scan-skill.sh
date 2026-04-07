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

result=$(honeybadger scan "$skill_dir" --paranoia family --format ndjson --offline 2>/dev/null | tail -1)
verdict=$(echo "$result" | jq -r '.verdict // "FAIL"')

case "$verdict" in
    FAIL)
        echo "BLOCKED: HoneyBadger scan FAILED for $skill_dir" >&2
        echo "$result" | jq -r '.reasoning // "Security scan failed"' >&2
        exit 2  # Claude Code hook convention: exit 2 = block
        ;;
    WARN)
        echo "WARNING: HoneyBadger found issues in $skill_dir" >&2
        echo "$result" | jq -r '.reasoning // "Security warnings found"' >&2
        exit 0  # Allow with warning. Change to exit 2 to block.
        ;;
    *)
        exit 0
        ;;
esac
