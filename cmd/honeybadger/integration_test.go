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

func TestCLI_ForceFlag(t *testing.T) {
	cmd := exec.Command(testBinary, "scan", "anything", "--force", "--format", "ndjson")
	out, _ := cmd.CombinedOutput()
	result := findResultEvent(t, out)
	if result["verdict"] != "PASS" {
		t.Errorf("--force verdict = %q, want PASS", result["verdict"])
	}
	if cmd.ProcessState.ExitCode() != 0 {
		t.Errorf("--force exit code = %d, want 0", cmd.ProcessState.ExitCode())
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

// ---------------------------------------------------------------------------
// MCP in-process tests
// ---------------------------------------------------------------------------

func TestMCP_ScanVerdicts(t *testing.T) {
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

			s := newMCPServer()
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
