# HoneyBadger Usage Examples

## CLI

### Scan a public GitHub repo
    honeybadger scan github.com/someone/some-skill

### Scan with strict paranoia
    honeybadger scan github.com/someone/some-skill --paranoia strict

### Offline scan of a local directory
    honeybadger scan ./my-local-project --offline

### Human-readable output
    honeybadger scan github.com/someone/some-skill --format text

### Verify an update hasn't changed
    honeybadger scan github.com/someone/some-skill --installed-sha abc123...

### Detect MCP tool definition changes (rug-pull detection)
    honeybadger scan github.com/someone/some-mcp --installed-tool-hash def456...

### Force bypass (logs the bypass)
    honeybadger scan github.com/someone/some-skill --force

### Scan a monorepo subdirectory
    honeybadger scan github.com/someone/monorepo --path skills/my-skill

### Write audit trail to SQLite
    honeybadger scan github.com/someone/some-skill --db ./audit.db

## MCP Server

### Start as MCP server
    honeybadger --mcp-server

### JSON-RPC call example (tools/call)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "honeybadger_scan",
    "arguments": {
      "repo_url": "github.com/someone/some-skill",
      "paranoia": "family"
    }
  }
}
```

### MCP tool parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `repo_url` | string | Yes | GitHub or GitLab repository URL, or local filesystem path |
| `paranoia` | string | No | `minimal`, `family`, `strict`, or `paranoid` (default: `family`) |
| `installed_sha` | string | No | SHA256 of currently installed version archive |
| `installed_tool_hash` | string | No | SHA256 of installed MCP tool definitions |
| `path` | string | No | Subdirectory within repo to scan |

### Response example
```json
{
  "type": "result",
  "verdict": "PASS",
  "reasoning": "No findings at or above threshold",
  "key_finding": "",
  "finding_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "cve_count": 0,
  "cve_max_severity": "",
  "attested": false,
  "llm_model": "",
  "llm_used": false,
  "paranoia": "family",
  "effective_paranoia": "family",
  "scanned_at": "2026-04-05T12:00:00Z",
  "duration_ms": 3200
}
```

## NDJSON Output Events (CLI)

Each line is a self-contained JSON object:

```
{"type":"sandbox","available":false,"reason":"...","sandbox_type":"","effective_paranoia":"family"}
{"type":"progress","phase":"fetch","message":"Fetching repository..."}
{"type":"progress","phase":"scan","message":"Running security scanners..."}
{"type":"finding","severity":"HIGH","check":"secrets","file":"config.go","line":3,"message":"..."}
{"type":"health","stars":42,"contributors":3,"age_days":365,"last_commit_days":7,...}
{"type":"result","verdict":"FAIL","reasoning":"...","finding_counts":{...},...}
```

## Exit Codes (CLI)

| Code | Meaning |
|------|---------|
| 0 | PASS -- safe to install |
| 1 | WARN -- review recommended |
| 2 | FAIL -- do not install |
| 3 | Error or unknown verdict |

The MCP server returns errors inline in the tool result rather than using exit codes.

## CI/CD Integration

### GitHub Action step
```yaml
- name: Security scan before deploy
  run: |
    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest
    honeybadger scan github.com/${{ github.repository }} --paranoia family
```
