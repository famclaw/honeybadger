#!/usr/bin/env bash
# Execute bit required: invoked directly from release workflow and Makefile.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 BINARY REPOSITORY REPORT_PATH" >&2
  exit 2
fi
BINARY=$1
REPO=$2
REPORT=$3
if [[ ! -x "$BINARY" ]]; then
  echo "::error::Scanner binary missing or not executable: $BINARY" >&2
  exit 1
fi
if [[ ! -d "$REPO" ]]; then
  echo "::error::Repository path missing: $REPO" >&2
  exit 1
fi
mkdir -p "$(dirname "$REPORT")"
if "$BINARY" scan "$REPO" --paranoia paranoid --offline --format ndjson >"$REPORT"; then
  SCANNER_EXIT=0
else
  SCANNER_EXIT=$?
fi
cat "$REPORT" || { echo "::error::Could not read self-check report" >&2; exit 1; }

# Validate every non-empty line as JSON and identify only top-level result records.
RESULT_COUNT=0
VERDICT=
LINE_NO=0
RECORD_COUNT=0
RESULT_RECORD_NO=0
while IFS= read -r line || [[ -n "$line" ]]; do
  LINE_NO=$((LINE_NO + 1))
  [[ -z "$line" ]] && continue
  RECORD_COUNT=$((RECORD_COUNT + 1))
  if ! printf '%s\n' "$line" | jq -e 'type == "object"' >/dev/null 2>&1; then
    echo "::error::Invalid NDJSON stream at line $LINE_NO" >&2
    exit 1
  fi
  TYPE=$(printf '%s\n' "$line" | jq -r 'if type == "object" then .type // "" else "" end' 2>/dev/null || true)
  if [[ "$TYPE" == "result" ]]; then
    RESULT_COUNT=$((RESULT_COUNT + 1))
    RESULT_RECORD_NO=$RECORD_COUNT
    if ! VERDICT=$(printf '%s\n' "$line" | jq -er 'select(.type == "result") | .verdict | select(type == "string")' 2>/dev/null); then
      echo "::error::Malformed terminal result or missing verdict" >&2
      exit 1
    fi
  fi
done < "$REPORT"

if [[ "$RESULT_COUNT" -eq 0 ]]; then
  echo "::error::No terminal result in self-check report" >&2
  exit 1
fi
if [[ "$RESULT_COUNT" -ne 1 ]]; then
  echo "::error::Multiple terminal result records found — scan output is malformed" >&2
  exit 1
fi
if [[ "$RESULT_RECORD_NO" -ne "$RECORD_COUNT" ]]; then
  echo "::error::Result record is not terminal in self-check report" >&2
  exit 1
fi
case "$VERDICT" in
  PASS) EXPECTED=0 ;;
  WARN) EXPECTED=1 ;;
  FAIL) EXPECTED=2 ;;
  INCOMPLETE) EXPECTED=4 ;;
  *) echo "::error::Invalid verdict: $VERDICT" >&2; exit 1 ;;
esac
if [[ "$SCANNER_EXIT" -ne "$EXPECTED" ]]; then
  echo "::error::Exit/verdict mismatch: exit=$SCANNER_EXIT verdict=$VERDICT expected=$EXPECTED" >&2
  exit 1
fi
case "$VERDICT" in
  PASS|WARN) echo "Self-check verdict=$VERDICT (exit=$SCANNER_EXIT)" ;;
  *) echo "::error::Self-check verdict=$VERDICT — aborting release" >&2; exit 1 ;;
esac
