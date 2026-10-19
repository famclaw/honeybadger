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
result=$(honeybadger scan "$skill_dir" --paranoia family --format ndjson --offline 2>/dev/null | jq -c 'select(.type=="result")' | tail -1) || scan_status=$?

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
