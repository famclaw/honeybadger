# HoneyBadger Detection Rules

Rules are YAML files that define detection patterns for HoneyBadger scanners.

## Rule Kinds

### `pattern`
Regex-based detection. Each rule contains one or more regex patterns tested against file content line by line.

### `dictionary`
List-based detection. The `packages` field holds a list of strings used for exact or proximity matching (e.g., typosquat detection via edit distance).

## YAML Schema

```yaml
id: unique-rule-id          # required, must be unique across all rules
kind: pattern                # required: "pattern" or "dictionary"
scanner: supplychain         # required: scanner that uses this rule
category: remote_exec        # required: grouping category
severity: HIGH               # required: CRITICAL, HIGH, MEDIUM, LOW, or INFO
signal: override_phrase      # optional: signal type for the scanner
message: Human-readable msg  # required: finding message

# For kind: pattern
patterns:
  - regex: 'curl[^|]+\|\s*(ba)?sh'
    description: curl piped to bash/sh

# For kind: dictionary
packages:
  - react
  - express
```

## Directory Layout

```
rules/
  supplychain/
    patterns/         # pattern rules for the supplychain scanner
    dictionaries/     # dictionary rules for the supplychain scanner
  skillsafety/
    prompt_injection/ # prompt injection override patterns
    exfil_intent/     # sensitive paths and webhook domain dictionaries
```

## Custom Rules

Place custom YAML rule files in `~/.honeybadger/rules/` or set `HONEYBADGER_RULES_DIR` to a directory path. You can also use `--rules-dir` on the CLI.

Custom rules with the same `id` as a built-in rule will replace the built-in version.

## Runtime Behavior

Rules are embedded at build time and loaded automatically. Scanners fall back to compiled Go globals when no rules are loaded (backward compatibility for tests).
