package mcptool

import "strings"

// mcpDepMarkers are dependency-manifest substrings that indicate the repo
// builds an MCP server.
var mcpDepMarkers = map[string][]string{
	"go.mod":           {"mark3labs/mcp-go", "modelcontextprotocol/go-sdk", "metoro-io/mcp-golang"},
	"package.json":     {"@modelcontextprotocol/sdk", "fastmcp", "mcp-framework"},
	"requirements.txt": {"mcp", "fastmcp"},
	"pyproject.toml":   {"mcp", "fastmcp"},
}

// hasMCPDependency reports whether any dependency manifest references an MCP SDK.
func hasMCPDependency(files map[string][]byte) bool {
	for path, content := range files {
		base := path
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		markers, ok := mcpDepMarkers[base]
		if !ok {
			continue
		}
		text := string(content)
		for _, m := range markers {
			if depMatches(base, text, m) {
				return true
			}
		}
	}
	return false
}

// depMatches checks a marker against manifest text. For requirements.txt and
// pyproject.toml the bare names "mcp"/"fastmcp" must match a dependency token,
// not an arbitrary substring.
func depMatches(base, text, marker string) bool {
	if base == "requirements.txt" || base == "pyproject.toml" {
		for _, line := range strings.Split(text, "\n") {
			tok := strings.TrimSpace(line)
			tok = strings.Trim(tok, `"' ,`)
			for _, sep := range []string{"==", ">=", "<=", "~=", ">", "<", "="} {
				if i := strings.Index(tok, sep); i >= 0 {
					tok = tok[:i]
				}
			}
			if strings.TrimSpace(tok) == marker {
				return true
			}
		}
		return false
	}
	return strings.Contains(text, marker)
}
