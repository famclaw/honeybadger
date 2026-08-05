//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/famclaw/honeybadger/internal/engine"
	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/testfixture"
)

var testBinary string

func TestMain(m *testing.M) {
	// Build binary to temp location
	dir, err := os.MkdirTemp("", "honeybadger-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "honeybadger")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s\n%s", err, out)
		os.Exit(1)
	}
	testBinary = bin
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func findResultEvent(t *testing.T, output []byte) map[string]any {
	t.Helper()
	for _, line := range bytes.Split(output, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if json.Unmarshal(line, &event) == nil {
			if event["type"] == "result" {
				return event
			}
		}
	}
	t.Fatalf("no result event found in output:\n%s", output)
	return nil
}

func countFindings(t *testing.T, output []byte) int {
	t.Helper()
	count := 0
	for _, line := range bytes.Split(output, []byte("\n")) {
		var event map[string]any
		if json.Unmarshal(line, &event) == nil {
			if event["type"] == "finding" || event["type"] == "cve" {
				count++
			}
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// CLI subprocess tests — table-driven
// ---------------------------------------------------------------------------

func TestCLI_ScanVerdicts(t *testing.T) {
	tests := []struct {
		name        string
		repo        *fetch.Repo
		paranoia    string
		wantVerdict string // PASS, WARN, or FAIL; empty = don't assert
		wantExit    int    // expected exit code; -1 = don't assert
		minFindings int
	}{
		{"clean at family", testfixture.CleanRepo(), "family", "PASS", 0, 0},
		{"clean at strict", testfixture.CleanRepo(), "strict", "FAIL", 2, 1}, // missing SKILL.md triggers MEDIUM finding at strict
		{"secrets at family", testfixture.SecretsRepo(), "family", "FAIL", 2, 1},
		{"secrets at minimal", testfixture.SecretsRepo(), "minimal", "FAIL", 2, 1},
		{"supplychain at minimal", testfixture.SupplyChainRepo(), "minimal", "PASS", 0, 0},
		{"supplychain at family", testfixture.SupplyChainRepo(), "family", "FAIL", 2, 1},
		{"meta mismatch at family", testfixture.MetaMismatchRepo(), "family", "", -1, 1},
		{"attestation at family", testfixture.AttestationRepo(), "family", "PASS", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testfixture.WriteToDir(t, tt.repo)

			cmd := exec.Command(testBinary, "scan", dir, "--paranoia", tt.paranoia, "--format", "ndjson", "--offline")
			out, _ := cmd.CombinedOutput()
			exitCode := cmd.ProcessState.ExitCode()

			result := findResultEvent(t, out)

			if tt.wantVerdict != "" {
				verdict, _ := result["verdict"].(string)
				if verdict != tt.wantVerdict {
					t.Errorf("verdict = %q, want %q\noutput: %s", verdict, tt.wantVerdict, out)
				}
			}
			if tt.wantExit >= 0 && exitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d\noutput: %s", exitCode, tt.wantExit, out)
			}
			if findings := countFindings(t, out); findings < tt.minFindings {
				t.Errorf("findings = %d, want >= %d\noutput: %s", findings, tt.minFindings, out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CLI special mode tests
// ---------------------------------------------------------------------------

// Regression for issue #82: `honeybadger scan --force` must NOT bypass
// analysis and report VERDICT: PASS.
//
// Previously the --force short-circuit emitted a bare PASS result with zero
// findings and zero duration after performing no work at all -- indistinguishable
// from a clean scan and strictly wrong for a security gate. The flag's own help
// text reads "force scan even if already audited", so --force must run the
// scanners. This test scans a repo containing a hardcoded secret: with --force
// the scan must still run and FAIL. It FAILS against the buggy code (PASS, 0
// findings, 0ms) and PASSES once the short-circuit is removed.
func TestCLI_ForceFlagRunsAnalysis(t *testing.T) {
	dir := testfixture.WriteToDir(t, testfixture.SecretsRepo())

	cmd := exec.Command(testBinary, "scan", dir,
		"--force", "--paranoia", "family", "--format", "ndjson", "--offline")
	out, _ := cmd.CombinedOutput()
	result := findResultEvent(t, out)

	verdict, _ := result["verdict"].(string)

	// A repo with a hardcoded secret must never report PASS -- especially via
	// --force, which is required to run the analysis.
	if verdict == "PASS" {
		t.Errorf("--force reported PASS for a repo containing secrets; "+
			"analysis was bypassed\n%s", out)
	}

	// Real findings must be present -- the scan actually executed.
	if findings := countFindings(t, out); findings == 0 {
		t.Errorf("--force produced 0 findings; analysis did not run\n%s", out)
	}

	// A real scan takes a measurable amount of time. The buggy short-circuit
	// emitted no duration_ms at all (Duration: 0ms).
	if dur, ok := result["duration_ms"].(float64); !ok || dur == 0 {
		t.Errorf("--force duration_ms = %v, expected > 0 (analysis did not run)\n%s",
			result["duration_ms"], out)
	}

	// Exit code must reflect the real verdict, never a silent 0 pass. Since this
	// repo contains a hardcoded secret, the scan must FAIL and the exit code must
	// be non-zero. The check is on the exit code directly — not gated on
	// `verdict != "PASS"` — because the --force bypass bug is itself what
	// produces verdict "PASS"; gating on that clause would make this assertion
	// dead (false exactly when the bug re-emerges).
	if exit := cmd.ProcessState.ExitCode(); exit == 0 {
		t.Errorf("--force exited 0 despite a repo containing secrets; expected non-zero\n%s", out)
	}
}

// Regression companion: --force must also bypass the --installed-sha audit
// cache so it truly "forces a scan even if already audited". This test proves
// the cache is real (matching SHA without --force short-circuits to PASS) and
// that --force defeats it (scan runs against a repo with a secret => FAIL).
func TestCLI_ForceFlagBYPASSSSHACache(t *testing.T) {
	dir := testfixture.WriteToDir(t, testfixture.SecretsRepo())
	installedSHA := engine.ComputeRepoHash(testfixture.SecretsRepo())

	// Without --force, a matching installed SHA short-circuits to PASS (audit
	// cache is real and performs hash-comparison work).
	cmd := exec.Command(testBinary, "scan", dir,
		"--installed-sha", installedSHA,
		"--paranoia", "family", "--format", "ndjson", "--offline")
	out, _ := cmd.CombinedOutput()
	result := findResultEvent(t, out)
	if verdict, _ := result["verdict"].(string); verdict != "PASS" {
		t.Errorf("matching --installed-sha without --force verdict = %q, want PASS "+
			"(proves the audit cache hash matches)\n%s", verdict, out)
	}

	// With --force the cache is bypassed: the scan must run and FAIL.
	cmdForced := exec.Command(testBinary, "scan", dir,
		"--force", "--installed-sha", installedSHA,
		"--paranoia", "family", "--format", "ndjson", "--offline")
	outF, _ := cmdForced.CombinedOutput()
	resultF := findResultEvent(t, outF)
	if verdict, _ := resultF["verdict"].(string); verdict == "PASS" {
		t.Errorf("--force with matching --installed-sha reported PASS; "+
			"the audit cache should have been bypassed\n%s", outF)
	}
}

func TestCLI_Version(t *testing.T) {
	cmd := exec.Command(testBinary, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "honeybadger") {
		t.Errorf("--version output %q does not contain 'honeybadger'", string(out))
	}
}

func TestCLI_TextFormat(t *testing.T) {
	dir := testfixture.WriteToDir(t, testfixture.CleanRepo())
	cmd := exec.Command(testBinary, "scan", dir, "--format", "text", "--offline")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "VERDICT") {
		t.Errorf("text output should contain VERDICT block, got:\n%s", out)
	}
}

// Regression: text format verdict block showed "0 critical, 0 high, 0 medium, 0 low"
// even when there were actual findings, because the emitter read the wrong key.
func TestCLI_TextFormatFindingCounts(t *testing.T) {
	dir := testfixture.WriteToDir(t, testfixture.SecretsRepo())
	cmd := exec.Command(testBinary, "scan", dir, "--format", "text", "--paranoia", "family", "--offline")
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, "VERDICT") {
		t.Fatalf("text output should contain VERDICT block, got:\n%s", output)
	}
	// The secrets fixture produces at least one finding. The verdict block must NOT
	// show all-zero counts, which was the symptom of the bug.
	if strings.Contains(output, "0 critical, 0 high, 0 medium, 0 low") {
		t.Errorf("finding counts are all zero in verdict block — regression: finding_counts key mismatch\noutput:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// MCP in-process tests
// ---------------------------------------------------------------------------

func TestMCP_ScanVerdicts(t *testing.T) {
	for _, key := range []string{"HONEYBADGER_LLM", "HONEYBADGER_LLM_KEY", "HONEYBADGER_LLM_MODEL"} {
		t.Setenv(key, "")
	}

	tests := []struct {
		name        string
		repo        *fetch.Repo
		paranoia    string
		wantVerdict string
	}{
		{"clean via MCP", testfixture.CleanRepo(), "family", "PASS"},
		{"secrets via MCP", testfixture.SecretsRepo(), "family", "FAIL"},
		{"supplychain via MCP", testfixture.SupplyChainRepo(), "family", "FAIL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := testfixture.WriteToDir(t, tt.repo)

			s := newMCPServer("")
			c, err := mcpclient.NewInProcessClient(s)
			if err != nil {
				t.Fatalf("NewInProcessClient: %v", err)
			}
			defer c.Close()

			ctx := context.Background()
			initReq := mcp.InitializeRequest{}
			initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
			initReq.Params.ClientInfo = mcp.Implementation{Name: "integration-test", Version: "1.0"}
			if _, err := c.Initialize(ctx, initReq); err != nil {
				t.Fatalf("Initialize: %v", err)
			}

			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "honeybadger_scan"
			callReq.Params.Arguments = map[string]any{
				"repo_url": dir,
				"paranoia": tt.paranoia,
			}

			result, err := c.CallTool(ctx, callReq)
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("tool returned error: %+v", result.Content)
			}
			if len(result.Content) == 0 {
				t.Fatal("expected non-empty content")
			}

			text, ok := mcp.AsTextContent(result.Content[0])
			if !ok {
				t.Fatalf("expected TextContent, got %T", result.Content[0])
			}

			var resultMap map[string]any
			if err := json.Unmarshal([]byte(text.Text), &resultMap); err != nil {
				t.Fatalf("failed to parse result JSON: %v\nraw: %s", err, text.Text)
			}

			verdict, _ := resultMap["verdict"].(string)
			if verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q\nresult: %s", verdict, tt.wantVerdict, text.Text)
			}
		})
	}
}

// TestCLI_SelfScanNoFalsePositive is the regression guard for the self-check
// false-positive fix. honeybadger's own repository is a clean reference repo:
// it must not FAIL its own scan at any paranoia tier. A clean reference repo
// that FAILs strips all discriminating signal from the FAIL verdict — the
// graduated-paranoia design depends on this invariant holding.
func TestCLI_SelfScanNoFalsePositive(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	for _, tier := range []string{"family", "strict", "paranoid"} {
		t.Run(tier, func(t *testing.T) {
			cmd := exec.Command(testBinary, "scan", repoRoot,
				"--paranoia", tier, "--format", "ndjson", "--offline")
			out, _ := cmd.CombinedOutput()
			result := findResultEvent(t, out)
			if verdict, _ := result["verdict"].(string); verdict == "FAIL" {
				t.Errorf("self-scan at --paranoia %s returned FAIL; honeybadger "+
					"must pass its own scan\noutput: %s", tier, out)
			}
		})
	}
}
