package docs_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// docsDir returns the absolute path to the docs/ directory.
func docsDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Dir(filename)
}

// readDoc reads a doc file from the docs/ directory.
func readDoc(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(docsDir(t), name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(content)
}

// readSource reads a source file relative to the repo root.
func readSource(t *testing.T, relPath string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(docsDir(t), "..", relPath))
	if err != nil {
		t.Fatalf("reading %s: %v", relPath, err)
	}
	return string(content)
}

// allParanoiaLevels are the valid paranoia levels from scan.ParseParanoia.
var allParanoiaLevels = []string{"off", "minimal", "family", "strict", "paranoid"}

// --- Task 7: Paranoia Levels ---

func TestOpenClaw_ParanoiaLevelsDocumented(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")
	for _, level := range allParanoiaLevels {
		if !strings.Contains(doc, "`"+level+"`") {
			t.Errorf("OPENCLAW.md missing paranoia level %q", level)
		}
	}
}

func TestOpenClaw_ParanoiaTableMatchesREADME(t *testing.T) {
	openclaw := readDoc(t, "OPENCLAW.md")
	readme := readSource(t, "README.md")
	for _, level := range allParanoiaLevels {
		inOpenclaw := strings.Contains(openclaw, "| `"+level+"`")
		inReadme := strings.Contains(readme, "| "+level+" ")
		if inOpenclaw && !inReadme {
			t.Errorf("paranoia level %q in OPENCLAW.md but not in README.md table", level)
		}
		if inReadme && !inOpenclaw {
			t.Errorf("paranoia level %q in README.md but not in OPENCLAW.md table", level)
		}
	}
}

// --- Task 8: CLI Flags ---

func TestExamples_CLIFlagsExistInSource(t *testing.T) {
	_ = readDoc(t, "EXAMPLES.md") // verify file exists
	src := readSource(t, filepath.Join("cmd", "honeybadger", "main.go"))

	documentedFlags := []string{
		"--paranoia", "--format", "--offline", "--installed-sha",
		"--installed-tool-hash", "--force", "--path", "--db", "--mcp-server",
	}
	for _, flag := range documentedFlags {
		name := strings.TrimLeft(flag, "-")
		if !strings.Contains(src, `"`+name+`"`) && !strings.Contains(src, "--"+name) {
			t.Errorf("EXAMPLES.md documents %s but it is not defined in main.go", flag)
		}
	}
}

func TestExamples_ExitCodesMatchEngine(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")
	expectedCodes := map[string]string{
		"| 0 ": "PASS",
		"| 1 ": "WARN",
		"| 2 ": "FAIL",
		"| 3 ": "Error",
	}
	for code, meaning := range expectedCodes {
		if !strings.Contains(doc, code) {
			t.Errorf("EXAMPLES.md missing exit code row starting with %q", code)
		}
		if !strings.Contains(doc, meaning) {
			t.Errorf("EXAMPLES.md missing exit code meaning %q", meaning)
		}
	}
}

// --- Task 9: MCP Schema ---

func TestExamples_MCPParametersMatchSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")
	src := readSource(t, filepath.Join("cmd", "honeybadger", "mcp.go"))

	params := []string{"repo_url", "paranoia", "installed_sha", "installed_tool_hash", "path"}
	for _, param := range params {
		if !strings.Contains(src, `"`+param+`"`) {
			t.Errorf("EXAMPLES.md documents MCP param %q but it is not in mcp.go", param)
		}
		if !strings.Contains(doc, "| `"+param+"`") {
			t.Errorf("MCP param %q is in source but missing from EXAMPLES.md table", param)
		}
	}

	// Reverse check: params defined in mcp.go must be documented
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, `WithString("`) {
			start := strings.Index(line, `WithString("`) + len(`WithString("`)
			end := strings.Index(line[start:], `"`)
			if end > 0 {
				param := line[start : start+end]
				if !strings.Contains(doc, param) {
					t.Errorf("mcp.go defines param %q but EXAMPLES.md does not document it", param)
				}
			}
		}
	}
}

func TestOpenClaw_MCPToolNameMatchesSource(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")
	src := readSource(t, filepath.Join("cmd", "honeybadger", "mcp.go"))

	marker := `mcp.NewTool("`
	idx := strings.Index(src, marker)
	if idx < 0 {
		t.Fatal("could not find mcp.NewTool in mcp.go")
	}
	nameStart := idx + len(marker)
	nameEnd := strings.Index(src[nameStart:], `"`)
	toolName := src[nameStart : nameStart+nameEnd]

	if !strings.Contains(doc, toolName) {
		t.Errorf("OPENCLAW.md does not mention MCP tool name %q", toolName)
	}
}

// --- Task 10: Environment Variables ---

func TestOpenClaw_EnvVarsMatchSource(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")
	src := readSource(t, filepath.Join("cmd", "honeybadger", "main.go")) +
		readSource(t, filepath.Join("cmd", "honeybadger", "mcp.go"))

	envVars := []string{
		"GITHUB_TOKEN", "GITLAB_TOKEN",
		"HONEYBADGER_LLM", "HONEYBADGER_LLM_KEY", "HONEYBADGER_LLM_MODEL",
	}
	for _, env := range envVars {
		if !strings.Contains(doc, "`"+env+"`") {
			t.Errorf("env var %s not in OPENCLAW.md", env)
		}
		if !strings.Contains(src, `"`+env+`"`) {
			t.Errorf("OPENCLAW.md documents env var %s but it is not used in source", env)
		}
	}
}

// --- Task 11: Binary Targets & Config ---

func TestOpenClaw_BinaryTargetsMatchMakefile(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")
	makefile := readSource(t, "Makefile")

	// Binary names documented in OPENCLAW.md. The Makefile uses $(BINARY)-suffix
	// so we check for the suffix portion that appears literally in the Makefile.
	binaryNames := []string{
		"honeybadger-linux-arm64", "honeybadger-linux-armv7",
		"honeybadger-linux-amd64", "honeybadger-darwin-arm64",
		"honeybadger-darwin-amd64",
	}
	for _, bin := range binaryNames {
		if !strings.Contains(doc, bin) {
			t.Errorf("OPENCLAW.md missing binary target %q", bin)
		}
		// Makefile uses $(BINARY)-suffix, so check for the suffix after "honeybadger"
		suffix := strings.TrimPrefix(bin, "honeybadger")
		if !strings.Contains(makefile, suffix) {
			t.Errorf("OPENCLAW.md lists binary %q but Makefile does not build a target with suffix %q", bin, suffix)
		}
	}
}

func TestOpenClaw_ConfigExamplesHaveMCPServerFlag(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")

	sections := []string{"FamClaw", "OpenClaw", "PicoClaw"}
	for _, section := range sections {
		if !strings.Contains(doc, section) {
			t.Errorf("OPENCLAW.md missing config section for %q", section)
		}
	}
	if count := strings.Count(doc, "--mcp-server"); count < 3 {
		t.Errorf("OPENCLAW.md should have --mcp-server in all 3 config examples, found %d references", count)
	}
}

func TestExamples_ResponseSchemaFieldsMatchSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	requiredFields := []string{
		"verdict", "reasoning", "finding_counts", "cve_count",
		"cve_max_severity", "attested", "llm_used", "paranoia",
		"effective_paranoia", "scanned_at", "duration_ms",
	}
	for _, field := range requiredFields {
		if !strings.Contains(doc, `"`+field+`"`) {
			t.Errorf("EXAMPLES.md response example missing field %q", field)
		}
	}
}

func TestExamples_NDJSONEventTypesDocumented(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	eventTypes := []string{"sandbox", "progress", "finding", "health", "result"}
	for _, evt := range eventTypes {
		if !strings.Contains(doc, `"type":"`+evt+`"`) {
			t.Errorf("EXAMPLES.md NDJSON section missing event type %q", evt)
		}
	}
}

// --- Task 14: Claude Code Guide ---

func TestClaudeCode_MCPConfigValid(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	if !strings.Contains(doc, `"mcpServers"`) {
		t.Error("CLAUDE_CODE.md missing mcpServers config block")
	}
	if !strings.Contains(doc, `"honeybadger"`) {
		t.Error("CLAUDE_CODE.md missing honeybadger server name in config")
	}
	if !strings.Contains(doc, `"--mcp-server"`) {
		t.Error("CLAUDE_CODE.md missing --mcp-server arg in config")
	}
}

func TestClaudeCode_MCPParamsMatchSource(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")
	src := readSource(t, filepath.Join("cmd", "honeybadger", "mcp.go"))

	params := []string{"repo_url", "paranoia", "installed_sha", "installed_tool_hash", "path"}
	for _, param := range params {
		if !strings.Contains(src, `"`+param+`"`) {
			t.Errorf("param %q not in mcp.go source", param)
		}
		if !strings.Contains(doc, "`"+param+"`") {
			t.Errorf("CLAUDE_CODE.md missing MCP param %q", param)
		}
	}
}

func TestClaudeCode_EnvVarsDocumented(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	envVars := []string{
		"GITHUB_TOKEN", "GITLAB_TOKEN",
		"HONEYBADGER_LLM", "HONEYBADGER_LLM_KEY", "HONEYBADGER_LLM_MODEL",
	}
	for _, env := range envVars {
		if !strings.Contains(doc, env) {
			t.Errorf("CLAUDE_CODE.md missing env var %s", env)
		}
	}
}

func TestClaudeCode_SettingsPathsDocumented(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	if !strings.Contains(doc, ".claude/settings.local.json") {
		t.Error("CLAUDE_CODE.md missing project-level settings path (.claude/settings.local.json)")
	}
	if !strings.Contains(doc, "~/.claude/settings.json") {
		t.Error("CLAUDE_CODE.md missing user-level settings path (~/.claude/settings.json)")
	}
}

func TestClaudeCode_DockerAlternativeDocumented(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	if !strings.Contains(doc, "ghcr.io/famclaw/honeybadger") {
		t.Error("CLAUDE_CODE.md missing Docker image reference")
	}
	if !strings.Contains(doc, `"docker"`) {
		t.Error("CLAUDE_CODE.md missing Docker command in MCP config example")
	}
}
