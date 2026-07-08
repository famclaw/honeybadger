## HoneyBadger Agent Instructions

**What this is**  
Go security scanner for AI agent skills and MCP servers. Scans for hardcoded secrets, CVEs, supply-chain risk, and build provenance before install. CLI + MCP server modes. MIT licensed.

**Code structure**  
- Scanners in `internal/scanner/`: secrets, supplychain, cve, meta, capability, skillsafety, mcptool, attestation  
- Core types in `internal/scan/`: `Finding`, `Options`, helpers  
- Engine in `internal/engine/`: scanner list, verdict logic  
- Entry points: `cmd/honeybadger/main.go` (CLI), `cmd/honeybadger/mcp.go` (MCP)

**Coding rules**  
- Go language only  
- Every scanner change requires matching test fixture  
- Fixtures must build secrets at runtime (not hardcoded) to avoid GitHub push protection  
- Run `make self-check` before submitting (HoneyBadger scans itself)

**Build & test**  
- `make build`  
- `make test`  
- `make self-check`  
- Integration tests: `go test -tags integration ./...`

**Module path**  
`github.com/famclaw/honeybadger`
