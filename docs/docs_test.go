package docs_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
	if nameEnd < 0 {
		t.Fatal("could not parse MCP tool name in mcp.go")
	}
	toolName := src[nameStart : nameStart+nameEnd]

	if !strings.Contains(doc, toolName) {
		t.Errorf("EXAMPLES.md does not mention MCP tool name %q", toolName)
	}
}

// --- EXAMPLES.md Env Vars ---

func TestEnvVarsDocumentedInGuides(t *testing.T) {
	claudeDoc := readDoc(t, "CLAUDE_CODE.md")
	openclawDoc := readDoc(t, "INSTALLATION.md")
	src := readSource(t, filepath.Join("cmd", "honeybadger", "main.go")) +
		readSource(t, filepath.Join("cmd", "honeybadger", "mcp.go"))

	envVars := []string{
		"GITHUB_TOKEN", "HONEYBADGER_LLM",
	}
	for _, env := range envVars {
		if !strings.Contains(src, `"`+env+`"`) {
			t.Errorf("env var %s expected in source but not found", env)
		}
		if !strings.Contains(claudeDoc, env) {
			t.Errorf("CLAUDE_CODE.md missing env var %s", env)
		}
		if !strings.Contains(openclawDoc, env) {
			t.Errorf("INSTALLATION.md missing env var %s", env)
		}
	}
}

func TestExamples_ResponseSchemaFieldsMatchSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	requiredFields := []string{
		"verdict", "reasoning", "finding_counts", "cve_count",
		"cve_max_severity", "attested", "attested_basis", "llm_used", "paranoia",
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

// --- INSTALLATION.md Runtime Accuracy ---

// TestOpenCLAWMDRuntimeAccuracy validates docs/INSTALLATION.md is accurate.
func TestOpenCLAWMDRuntimeAccuracy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(docsDir(t), "INSTALLATION.md"))
	if err != nil {
		t.Fatalf("cannot read docs/INSTALLATION.md: %v", err)
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
				t.Errorf("INSTALLATION.md must NOT contain %q: %s", c.want, c.errMsg)
			} else if !c.absence && !found {
				t.Errorf("INSTALLATION.md must contain %q: %s", c.want, c.errMsg)
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

// --- Hook script doc drift (docs must mirror the canonical examples) ---

// TestDocs_HookScriptsMatchExamples asserts that the fenced hook script in each
// integration doc matches the canonical examples/*.sh file exactly.
func TestDocs_HookScriptsMatchExamples(t *testing.T) {
	cases := []struct {
		doc     string
		example string
	}{
		{"CLAUDE_CODE.md", "examples/claude-code/scan-skill.sh"},
		{"integrations/claude-code.md", "examples/claude-code/scan-skill.sh"},
		{"integrations/codex-cli.md", "examples/codex-cli/scan-skill.sh"},
	}
	for _, c := range cases {
		t.Run(c.doc, func(t *testing.T) {
			got := normalizeHook(hookScriptBlock(t, readDoc(t, c.doc)))
			want := normalizeHook(readSource(t, c.example))
			if got != want {
				t.Errorf("hook block in %s drifts from %s", c.doc, c.example)
			}
		})
	}
}

// hookScriptBlock returns the fenced bash block that is the scan-skill hook.
func hookScriptBlock(t *testing.T, doc string) string {
	t.Helper()
	var block string
	for _, section := range strings.Split(doc, "```bash") {
		if i := strings.Index(section, "```"); i > 0 &&
			strings.Contains(section[:i], "input=$(cat)") &&
			strings.Contains(section[:i], "honeybadger scan") {
			block = section[:i]
		}
	}
	if block == "" {
		t.Fatal("no scan-skill hook bash block found in doc")
	}
	return block
}

// normalizeHook trims CRLF and per-line trailing whitespace for comparison.
func normalizeHook(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " 	")
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

// --- Docs/binary alignment (product-audit P2) ---

// TestDocs_GoPrerequisiteMatchesGoMod asserts the Go prerequisite stated in
// README.md and INSTALLATION.md matches the `go` directive in go.mod, so the
// prerequisite cannot silently rot as the module version moves.
func TestDocs_GoPrerequisiteMatchesGoMod(t *testing.T) {
	gomod := readSource(t, "go.mod")
	var goVer string
	for _, line := range strings.Split(gomod, "\n") {
		if strings.HasPrefix(line, "go ") {
			goVer = strings.TrimSpace(strings.TrimPrefix(line, "go "))
			break
		}
	}
	if goVer == "" {
		t.Fatal("could not parse the go directive from go.mod")
	}
	for name, doc := range map[string]string{
		"README.md":       readSource(t, "README.md"),
		"INSTALLATION.md": readDoc(t, "INSTALLATION.md"),
	} {
		if !strings.Contains(doc, "Go "+goVer) {
			t.Errorf("%s does not state the Go %s prerequisite from go.mod", name, goVer)
		}
	}
}

// TestDocs_AuditTrailIsJSONL asserts no doc claims the --db audit trail is a
// SQLite database: it is JSONL, one JSON record per scan.
func TestDocs_AuditTrailIsJSONL(t *testing.T) {
	for name, doc := range map[string]string{
		"README.md":       readSource(t, "README.md"),
		"INSTALLATION.md": readDoc(t, "INSTALLATION.md"),
		"EXAMPLES.md":     readDoc(t, "EXAMPLES.md"),
	} {
		if strings.Contains(doc, "SQLite") {
			t.Errorf("%s still describes the audit trail as SQLite; --db writes JSONL", name)
		}
	}
	examples := readDoc(t, "EXAMPLES.md")
	if !strings.Contains(examples, "--db ./audit.jsonl") {
		t.Error("EXAMPLES.md must show the --db example with a .jsonl path")
	}
	readme := readSource(t, "README.md")
	if !strings.Contains(readme, "JSONL path for audit trail") {
		t.Error("README.md --db flag description must say the audit trail is JSONL")
	}
}

var releaseVersionRe = regexp.MustCompile(`\*\*v(\d+\.\d+\.\d+) released\*\*`)

// TestDocs_ReleasedVersionMatchesLatestTag asserts the version claimed by the
// README Status section equals the latest vX.Y.Z release tag in git — the
// drift the product audit found (README claimed v0.5.1 while v0.6.2 was the
// latest release). Skipped when git tags are unavailable.
func TestDocs_ReleasedVersionMatchesLatestTag(t *testing.T) {
	readme := readSource(t, "README.md")
	m := releaseVersionRe.FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("README.md Status section: could not find 'vX.Y.Z released'")
	}
	claimed := m[1]

	out, err := exec.Command("git", "tag", "--list", "v*").Output()
	if err != nil {
		t.Skipf("git tags unavailable: %v", err)
	}
	var best [3]int = [3]int{-1, -1, -1}
	bestTag := ""
	tagRe := regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
	for _, line := range strings.Split(string(out), "\n") {
		tm := tagRe.FindStringSubmatch(strings.TrimSpace(line))
		if tm == nil {
			continue
		}
		c, err := parseVer(tm)
		if err != nil {
			continue
		}
		if c[0] > best[0] || (c[0] == best[0] && c[1] > best[1]) ||
			(c[0] == best[0] && c[1] == best[1] && c[2] > best[2]) {
			best, bestTag = c, "v"+strings.Join(tm[1:], ".")
		}
	}
	if bestTag == "" {
		t.Skip("no vX.Y.Z tags found in git; skipping tag-cross-check")
	}
	if claimed != bestTag[1:] {
		t.Errorf("README claims v%s released but the latest git tag is %s", claimed, bestTag)
	}
}

func parseVer(tm []string) ([3]int, error) {
	var out [3]int
	for i, s := range tm[1:4] {
		n, err := strconv.Atoi(s)
		if err != nil {
			return out, err
		}
		out[i] = n
	}
	return out, nil
}

// TestDocs_ParanoidAllowlistLabeledUnimplemented asserts the docs no longer
// present the paranoid-tier allowlist as an implemented scanner (product-audit
// P2: it was advertised but never exists in scanner selection; CONTRIBUTING.md
// lists it as a known gap).
func TestDocs_ParanoidAllowlistLabeledUnimplemented(t *testing.T) {
	readme := readSource(t, "README.md")
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "| paranoid ") {
			if strings.Contains(line, "allowlist") {
				t.Errorf("README.md paranoid row lists the allowlist as an implemented scanner: %q", line)
			}
		}
	}
	if !strings.Contains(strings.ReplaceAll(readme, "\n", " "), "not yet implemented") {
		t.Error("README.md must explicitly say the paranoid allowlist is not yet implemented")
	}

	skill := readSource(t, "SKILL.md")
	found := false
	for _, line := range strings.Split(skill, "\n") {
		if strings.Contains(line, "**paranoid**") {
			found = true
			if strings.Contains(line, "allowlist enforcement") {
				t.Errorf("SKILL.md still presents the allowlist as implemented: %q", line)
			}
		}
	}
	if !found {
		t.Fatal("SKILL.md paranoid bullet not found")
	}
}

// TestDocs_AuditTrailProvenanceDocumented asserts the README documents the
// audit record provenance block, field by field.
func TestDocs_AuditTrailProvenanceDocumented(t *testing.T) {
	readme := readSource(t, "README.md")
	fields := []string{
		"provenance.source_digest",
		"provenance.rules_digest",
		"provenance.rules_dir",
		"provenance.policy_trusted",
		"provenance.suppress",
		"provenance.checks",
	}
	for _, f := range fields {
		if !strings.Contains(readme, f) {
			t.Errorf("README.md audit trail section missing %q", f)
		}
	}
	// Sanity: the fields the docs promise exist on the Go type.
	audit := readSource(t, filepath.Join("internal", "store", "audit.go"))
	for _, f := range []string{
		`json:"source_digest"`, `json:"rules_digest"`, `json:"rules_dir`,
		`json:"policy_trusted"`, `json:"suppress"`, `json:"checks"`,
	} {
		if !strings.Contains(audit, f) {
			t.Errorf("README documents %q but internal/store/audit.go lacks it", f)
		}
	}
}
