package docs_test

import (
	"fmt"
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

// --- Paranoia Levels (README + EXAMPLES) ---

func TestREADME_ParanoiaLevelsDocumented(t *testing.T) {
	readme := readSource(t, "README.md")
	for _, level := range allParanoiaLevels {
		if !strings.Contains(readme, "| "+level+" ") {
			t.Errorf("README.md missing paranoia level %q in table", level)
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

// --- EXAMPLES.md MCP Tool Name ---

func TestExamples_MCPToolNameMatchesSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")
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
		t.Errorf("EXAMPLES.md does not mention MCP tool name %q", toolName)
	}
}

// --- EXAMPLES.md Env Vars ---

func TestExamples_EnvVarsDocumented(t *testing.T) {
	src := readSource(t, filepath.Join("cmd", "honeybadger", "main.go")) +
		readSource(t, filepath.Join("cmd", "honeybadger", "mcp.go"))

	// Verify these env vars are actually used in source
	envVars := []string{
		"GITHUB_TOKEN", "GITLAB_TOKEN",
		"HONEYBADGER_LLM", "HONEYBADGER_LLM_KEY", "HONEYBADGER_LLM_MODEL",
	}
	for _, env := range envVars {
		if !strings.Contains(src, `"`+env+`"`) {
			t.Errorf("env var %s expected in source but not found", env)
		}
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

// --- SKILL.md Runtime Accuracy ---

// TestSKILLMDRuntimeAccuracy validates SKILL.md is correct for Claude Code
// and OpenClaw. These tests fail with the old SKILL.md, pass after the fix.
func TestSKILLMDRuntimeAccuracy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(docsDir(t), "..", "SKILL.md"))
	if err != nil {
		t.Fatalf("cannot read SKILL.md: %v", err)
	}
	content := string(raw)

	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		t.Fatal("SKILL.md missing YAML frontmatter (need opening and closing ---)")
	}
	fm := parts[1]
	body := parts[2]

	cases := []struct {
		name  string
		check func(fm, body string) error
	}{
		{
			"description is a trigger phrase not a tagline",
			func(fm, _ string) error {
				lower := strings.ToLower(fm)
				for _, kw := range []string{"use when", "scan", "check", "vet", "before install"} {
					if strings.Contains(lower, kw) {
						return nil
					}
				}
				return fmt.Errorf("description must be a trigger phrase — include 'use when', 'scan', 'check', or similar action words")
			},
		},
		{
			"no triggers field — not valid in Claude Code or OpenClaw",
			func(fm, _ string) error {
				if strings.Contains(fm, "triggers:") {
					return fmt.Errorf("'triggers' is not a valid SKILL.md field for Claude Code or OpenClaw — remove it; both runtimes use 'description' for triggering")
				}
				return nil
			},
		},
		{
			"no invoke field — not valid in either runtime",
			func(fm, _ string) error {
				if strings.Contains(fm, "\ninvoke:") || strings.HasPrefix(strings.TrimSpace(fm), "invoke:") {
					return fmt.Errorf("'invoke' is not a valid SKILL.md field — remove it; the skill body tells Claude how to invoke the binary")
				}
				return nil
			},
		},
		{
			"no chrome_devtools_mcp field — invented, not valid in either runtime",
			func(fm, _ string) error {
				if strings.Contains(fm, "chrome_devtools_mcp") {
					return fmt.Errorf("'chrome_devtools_mcp' is not a valid SKILL.md field — remove it")
				}
				return nil
			},
		},
		{
			"no bins_optional field — not valid in either runtime",
			func(fm, _ string) error {
				if strings.Contains(fm, "bins_optional") {
					return fmt.Errorf("'bins_optional' is not a valid SKILL.md field — use metadata.openclaw.requires.bins instead")
				}
				return nil
			},
		},
		{
			"has metadata.openclaw block for OpenClaw binary resolution",
			func(fm, _ string) error {
				if !strings.Contains(fm, `"openclaw"`) {
					return fmt.Errorf("missing metadata.openclaw block — OpenClaw needs this for binary resolution and auto-install")
				}
				return nil
			},
		},
		{
			"metadata.openclaw has requires.bins listing honeybadger",
			func(fm, _ string) error {
				if !strings.Contains(fm, `"bins"`) || !strings.Contains(fm, `"honeybadger"`) {
					return fmt.Errorf("metadata.openclaw.requires.bins must list 'honeybadger'")
				}
				return nil
			},
		},
		{
			"metadata.openclaw has install entry with go install command",
			func(fm, _ string) error {
				if !strings.Contains(fm, "go install") {
					return fmt.Errorf("metadata.openclaw.install must include a go install command so OpenClaw can auto-install the binary")
				}
				return nil
			},
		},
		{
			"skill body explains how to invoke the binary",
			func(_, body string) error {
				if !strings.Contains(body, "honeybadger scan") {
					return fmt.Errorf("skill body must include the exact 'honeybadger scan' command so Claude knows how to use it")
				}
				return nil
			},
		},
		{
			"skill body explains exit codes or verdict interpretation",
			func(_, body string) error {
				lower := strings.ToLower(body)
				hasVerdict := strings.Contains(lower, "verdict")
				hasExitCode := strings.Contains(lower, "exit code")
				if !hasVerdict || !hasExitCode {
					return fmt.Errorf("skill body must explain how to interpret output: include 'verdict' and 'exit code'")
				}
				return nil
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.check(fm, body); err != nil {
				t.Error(err)
			}
		})
	}
}

// --- OPENCLAW.md Runtime Accuracy ---

// TestOpenCLAWMDRuntimeAccuracy validates docs/OPENCLAW.md is accurate.
func TestOpenCLAWMDRuntimeAccuracy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(docsDir(t), "OPENCLAW.md"))
	if err != nil {
		t.Fatalf("cannot read docs/OPENCLAW.md: %v", err)
	}
	doc := string(raw)

	cases := []struct {
		name    string
		want    string
		absence bool
		errMsg  string
	}{
		{
			"documents correct OpenClaw workspace skills path",
			"~/.openclaw/workspace/skills/honeybadger", false,
			"must document ~/.openclaw/workspace/skills/honeybadger as the primary install path",
		},
		{
			"documents go install command for binary",
			"go install github.com/famclaw/honeybadger/cmd/honeybadger@latest", false,
			"must show the go install command",
		},
		{
			"documents openclaw skills list for verification",
			"openclaw skills list", false,
			"must show 'openclaw skills list' so user can verify skill loaded",
		},
		{
			"documents Docker setupCommand for sandboxed agents",
			"setupCommand", false,
			"must include Docker sandbox setup instructions",
		},
		{
			"documents cosign verification",
			"cosign verify-blob", false,
			"must include cosign verification instructions for downloaded binaries",
		},
		{
			"does not reference non-existent ClawHub listing",
			"clawhub install honeybadger", true,
			"must not reference 'clawhub install honeybadger' — HoneyBadger is not on ClawHub yet",
		},
		{
			"does not reference npx clawhub for install",
			"npx clawhub@latest install honeybadger", true,
			"must not use 'npx clawhub install honeybadger' — not published to ClawHub",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found := strings.Contains(doc, c.want)
			if c.absence && found {
				t.Errorf("OPENCLAW.md must NOT contain %q: %s", c.want, c.errMsg)
			} else if !c.absence && !found {
				t.Errorf("OPENCLAW.md must contain %q: %s", c.want, c.errMsg)
			}
		})
	}
}

// --- CLAUDE_CODE.md Runtime Accuracy ---

// TestClaudeCodeMDRuntimeAccuracy validates docs/CLAUDE_CODE.md is accurate.
func TestClaudeCodeMDRuntimeAccuracy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(docsDir(t), "CLAUDE_CODE.md"))
	if err != nil {
		t.Fatalf("cannot read docs/CLAUDE_CODE.md: %v", err)
	}
	doc := string(raw)

	cases := []struct {
		name    string
		want    string
		absence bool
		errMsg  string
	}{
		{
			"documents correct Claude Code skills directory",
			"~/.claude/skills/honeybadger", false,
			"must document ~/.claude/skills/honeybadger as the global install path",
		},
		{
			"documents project-scoped .claude/skills path",
			".claude/skills/honeybadger", false,
			"must document .claude/skills/honeybadger for project-scoped installation",
		},
		{
			"documents claude mcp add command for MCP server",
			"claude mcp add honeybadger", false,
			"must show 'claude mcp add honeybadger' for MCP server registration",
		},
		{
			"documents .mcp.json for project MCP configuration",
			".mcp.json", false,
			"must show .mcp.json example for project-level MCP config",
		},
		{
			"documents auto-triggering via description matching",
			"auto-trigger", false,
			"must explain that skills auto-trigger based on description matching",
		},
		{
			"documents cosign verification",
			"cosign verify-blob", false,
			"must include cosign verification instructions",
		},
		{
			"does not claim triggers field is read by Claude Code",
			"Claude Code reads the triggers field", true,
			"must not claim 'triggers' field is read by Claude Code — it is not",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found := strings.Contains(doc, c.want)
			if c.absence && found {
				t.Errorf("CLAUDE_CODE.md must NOT contain %q: %s", c.want, c.errMsg)
			} else if !c.absence && !found {
				t.Errorf("CLAUDE_CODE.md must contain %q: %s", c.want, c.errMsg)
			}
		})
	}
}
