package mcptool

import (
	"regexp"
	"sort"

	"github.com/famclaw/honeybadger/internal/fetch"
)

var (
	// goNewToolRe matches mcp.NewTool("name", ... WithDescription("desc") ...)
	// [^)]*? prevents bridging across two NewTool calls (stops at the first ")").
	goNewToolRe = regexp.MustCompile(`(?s)NewTool\(\s*"([^"]+)"[^)]*?WithDescription\(\s*"([^"]*)"`)
	// goStructRe matches Tool{Name: "name", Description: "desc"}
	goStructRe = regexp.MustCompile(`(?s)Tool\{[^}]*?Name:\s*"([^"]+)"[^}]*?Description:\s*"([^"]*)"`)
	// goRegisterRe matches RegisterTool("name", "desc", ...)
	goRegisterRe = regexp.MustCompile(`RegisterTool\(\s*"([^"]+)"\s*,\s*"([^"]*)"`)
	// tsRegisterRe matches server.registerTool("name", { ... description: "desc" ... })
	tsRegisterRe = regexp.MustCompile(`(?s)registerTool\(\s*["']([^"']+)["']\s*,\s*\{[^}]*?description:\s*["']([^"']*)["']`)
	// tsServerToolRe matches server.tool("name", "desc", ...)
	tsServerToolRe = regexp.MustCompile(`\.tool\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']`)
	// pyToolRe matches Tool(name="name", description="desc", ...)
	pyToolRe = regexp.MustCompile(`(?s)Tool\(\s*name\s*=\s*["']([^"']+)["']\s*,\s*description\s*=\s*["']([^"']*)["']`)
)

// extractFromSource heuristically extracts (name, description) tool definitions
// from repo source. Recall is high for Go, best-effort for TypeScript/Python.
// Returns a name-sorted, deduplicated slice.
func extractFromSource(repo *fetch.Repo) []ToolDef {
	byName := map[string]ToolDef{}
	for path, content := range repo.Files {
		if !isExtractableSource(path) {
			continue
		}
		text := string(content)
		for _, td := range extractGo(text) {
			addTool(byName, td, path)
		}
		for _, td := range extractTSPython(text) {
			addTool(byName, td, path)
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ToolDef, 0, len(names))
	for _, n := range names {
		out = append(out, byName[n])
	}
	return out
}

// isExtractableSource reports whether a path is a source file worth scanning.
func isExtractableSource(path string) bool {
	for _, suf := range []string{".go", ".ts", ".js", ".mts", ".py"} {
		if len(path) >= len(suf) && path[len(path)-len(suf):] == suf {
			return true
		}
	}
	return false
}

// addTool inserts a tool, keeping the first occurrence per name.
func addTool(byName map[string]ToolDef, td ToolDef, path string) {
	if td.Name == "" {
		return
	}
	if _, exists := byName[td.Name]; exists {
		return
	}
	td.SourceFile = path
	byName[td.Name] = td
}

func extractGo(text string) []ToolDef {
	var out []ToolDef
	for _, re := range []*regexp.Regexp{goNewToolRe, goStructRe, goRegisterRe} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, ToolDef{Name: m[1], Description: m[2]})
		}
	}
	return out
}

func extractTSPython(text string) []ToolDef {
	var out []ToolDef
	for _, re := range []*regexp.Regexp{tsRegisterRe, tsServerToolRe, pyToolRe} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, ToolDef{Name: m[1], Description: m[2]})
		}
	}
	return out
}
