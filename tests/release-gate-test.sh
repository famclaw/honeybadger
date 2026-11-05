#!/usr/bin/env bash
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HELPER="$ROOT/scripts/release-gate.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

run_case() {
  name=$1; exit_code=$2; payload=$3; expected=$4; mode=${5:-ok}
  fake="$TMP/fake-$name"; report="$TMP/report-$name"
  if [[ $mode == missing ]]; then fake="$TMP/not-a-binary"; else
    cat >"$fake" <<'FAKE'
#!/usr/bin/env bash
printf '%b\n' "$FIXTURE"
exit "$FIXTURE_EXIT"
FAKE
    chmod +x "$fake"
  fi
  if FIXTURE="$payload" FIXTURE_EXIT="$exit_code" "$HELPER" "$fake" "$ROOT" "$TMP/self-report-$name.json" >"$report" 2>&1; then actual=0; else actual=$?; fi
  if [[ $mode != missing && ! -s "$TMP/self-report-$name.json" ]]; then printf 'FAIL %s: report artifact missing or empty\n' "$name"; cat "$report"; return 1; fi
  if [[ $actual -eq $expected ]]; then printf 'PASS %s (got %s)\n' "$name" "$actual"; return 0; fi
  printf 'FAIL %s: expected %s got %s\n' "$name" "$expected" "$actual"; cat "$report"; return 1
}

cases=(
  'pass|0|{"type":"result","verdict":"PASS"}|0|ok'
  'warn|1|{"type":"result","verdict":"WARN"}|0|ok'
  'fail|2|{"type":"result","verdict":"FAIL"}|1|ok'
  'incomplete|4|{"type":"result","verdict":"INCOMPLETE"}|1|ok'
  'error-pass-text|3|{"type":"result","verdict":"PASS"}|1|ok'
  'exit0-no-result|0|{"type":"finding"}|1|ok'
  'malformed-json|0|{not json}|1|ok'
  'missing-verdict|0|{"type":"result"}|1|ok'
  'unknown-verdict|0|{"type":"result","verdict":"MAYBE"}|1|ok'
  'pass-exit1|1|{"type":"result","verdict":"PASS"}|1|ok'
  'warn-exit0|0|{"type":"result","verdict":"WARN"}|1|ok'
  'fail-exit0|0|{"type":"result","verdict":"FAIL"}|1|ok'
  'incomplete-exit2|2|{"type":"result","verdict":"INCOMPLETE"}|1|ok'
  'missing-binary|0||1|missing'
  'whitespace-valid|0|{"type": "result", "verdict": "PASS"}|0|ok'
  'nested-type-only|0|{"type":"finding","nested":{"type":"result","verdict":"PASS"}}|1|ok'
  'two-results|0|{"type":"result","verdict":"FAIL"}\n{"type":"result","verdict":"PASS"}|1|ok'
  'malformed-prefix|0|NOT_JSON\n{"type":"result","verdict":"PASS"}|1|ok'
  'mismatch-warn2|2|{"type":"result","verdict":"WARN"}|1|ok'
  'mismatch-incomplete0|0|{"type":"result","verdict":"INCOMPLETE"}|1|ok'
  'nonobject-json|0|[]\n{"type":"result","verdict":"PASS"}|1|ok'
  'multiple-json-values|0|{"type":"finding"} {"type":"result","verdict":"PASS"}|1|ok'
  'nested-plus-real-result|0|{"type":"finding","nested":{"type":"result","verdict":"FAIL"}}\n{"type":"result","verdict":"PASS"}|0|ok'
)
for item in "${cases[@]}"; do
  IFS='|' read -r name code payload expected mode <<<"$item"
  if ! run_case "$name" "$code" "$payload" "$expected" "$mode"; then FAILURES=$((FAILURES + 1)); fi
done
printf 'Summary: %d cases, %d failures\n' "${#cases[@]}" "$FAILURES"
exit "$FAILURES"
