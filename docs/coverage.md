# Coverage completeness

When honeybadger fetches a remote repository it may be unable to read every file.
In those cases it emits a `coverage-incomplete` finding so the consumer knows the
verdict was computed on a partial read.

## When coverage is incomplete

| Condition | Trigger | Finding severity |
|---|---|---|
| GitHub tree truncated | The tree API responds with `"truncated": true` (repo too large to enumerate in one request, typically > 100 k entries) | HIGH |
| File exceeds size cap | A blob exceeds `HONEYBADGER_MAX_FILE_BYTES` on the GitHub contents API (403 response or decoded size exceeds the cap) | HIGH |

## Effect on the verdict

A `coverage-incomplete` finding with type `"coverage-incomplete"` **always** forces the
verdict to `FAIL`, regardless of the paranoia level.  This prevents a `PASS` from being
reported when a significant portion of the repository was not scanned.

## Configuration

### File size cap

The maximum file size that honeybadger will fetch is controlled by the
`HONEYBADGER_MAX_FILE_BYTES` environment variable.

```
export HONEYBADGER_MAX_FILE_BYTES=5242880  # 5 MB
```

The default is **1 MB** (`1048576` bytes).  Raise this value only if your
repositories legitimately contain large text files that must be scanned.

> **Constraint:** honeybadger never attempts to download files that exceed the cap.
> The cap is a resource-control measure; the finding above signals which files were
> skipped.

## Example output (NDJSON)

```json
{"type":"coverage-incomplete","severity":"HIGH","check":"github-tree","file":"vendor/large-binary-dataset.json","message":"File vendor/large-binary-dataset.json exceeds 1048576-byte size cap and was not scanned"}
{"type":"coverage-incomplete","severity":"HIGH","check":"github-tree","message":"GitHub tree API returned truncated: true — evil-org/malicious-skill is too large to enumerate fully; some files were not scanned"}
```
