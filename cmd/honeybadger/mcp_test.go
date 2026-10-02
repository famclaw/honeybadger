package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestMCPServerToolRegistered(t *testing.T) {
	s := newMCPServer("")

	// Use in-process client to verify tool registration
	c, err := mcpclient.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0"}
	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	toolsResult, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(toolsResult.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(toolsResult.Tools))
	}

	tool := toolsResult.Tools[0]
	if tool.Name != "honeybadger_scan" {
		t.Errorf("tool name = %q, want honeybadger_scan", tool.Name)
	}

	// Verify the tool has the expected input schema properties
	props := tool.InputSchema.Properties

	expectedProps := []string{"repo_url", "paranoia", "installed_sha", "installed_tool_hash", "path"}
	for _, prop := range expectedProps {
		if _, exists := props[prop]; !exists {
			t.Errorf("missing property %q in input schema", prop)
		}
	}

	// Verify repo_url is required
	found := false
	for _, r := range tool.InputSchema.Required {
		if r == "repo_url" {
			found = true
			break
		}
	}
	if !found {
		t.Error("repo_url should be in required list")
	}
}

func TestMCPServerHandlerLocalRepo(t *testing.T) {
	s := newMCPServer("")

	c, err := mcpclient.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0"}
	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Create a temp directory with a simple Go file to scan
	dir := t.TempDir()
	writeTestFile(t, dir, "main.go", "package main\n\nfunc main() {}\n")
	writeTestFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.21\n")

	req := mcp.CallToolRequest{}
	req.Params.Name = "honeybadger_scan"
	req.Params.Arguments = map[string]any{
		"repo_url": dir,
		"paranoia": "minimal",
	}

	result, err := c.CallTool(ctx, req)
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

	// Parse the JSON result
	var resultMap map[string]any
	if err := json.Unmarshal([]byte(text.Text), &resultMap); err != nil {
		t.Fatalf("failed to parse result JSON: %v\nraw: %s", err, text.Text)
	}

	// Verify verdict is present and valid
	verdict, ok := resultMap["verdict"].(string)
	if !ok {
		t.Fatalf("verdict not a string: %v", resultMap["verdict"])
	}
	if verdict != "PASS" && verdict != "WARN" && verdict != "FAIL" {
		t.Errorf("unexpected verdict %q, want PASS/WARN/FAIL", verdict)
	}

	// Verify other required fields
	if _, ok := resultMap["reasoning"]; !ok {
		t.Error("missing 'reasoning' in result")
	}
	if _, ok := resultMap["paranoia"]; !ok {
		t.Error("missing 'paranoia' in result")
	}
	if _, ok := resultMap["scanned_at"]; !ok {
		t.Error("missing 'scanned_at' in result")
	}
}

func TestMCPServerHandlerMissingRepoURL(t *testing.T) {
	s := newMCPServer("")

	c, err := mcpclient.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0"}
	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	req := mcp.CallToolRequest{}
	req.Params.Name = "honeybadger_scan"
	req.Params.Arguments = map[string]any{}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	// Should return an error result, not a protocol error
	if !result.IsError {
		t.Error("expected IsError=true for missing repo_url")
	}
}

func TestMCPServerHandlerInvalidParanoia(t *testing.T) {
	s := newMCPServer("")

	c, err := mcpclient.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0"}
	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	req := mcp.CallToolRequest{}
	req.Params.Name = "honeybadger_scan"
	req.Params.Arguments = map[string]any{
		"repo_url": "/nonexistent/path",
		"paranoia": "invalid_level",
	}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	// Should return an error result for invalid paranoia
	if !result.IsError {
		t.Error("expected IsError=true for invalid paranoia level")
	}
}

// TestMCPScanAppliesFileRolesAndIgnore asserts the MCP scan pipeline runs the
// same post-scan steps as the CLI: ApplyFileRoles re-weighting and
// .honeybadgerignore suppression, in the same relative order, before the LLM
// verdict and result construction.
//
// The test exercises the observable result difference, not the internal
// drop-vs-annotate semantics of ApplyFileRoles (which is being changed by a
// separate in-flight task): a repo without SKILL.md deterministically yields an
// INFO "cap-no-skill-md" finding; an identical repo whose .honeybadgerignore
// suppresses that rule must report a lower total finding count.
func TestMCPScanAppliesFileRolesAndIgnore(t *testing.T) {
	s := newMCPServer("")
	c, err := mcpclient.NewInProcessClient(s)
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

	// Directory A: minimal Go app, no SKILL.md, no .honeybadgerignore.
	// The capability scanner emits an INFO "cap-no-skill-md" finding.
	dirA := t.TempDir()
	writeTestFile(t, dirA, "main.go", "package main\n\nfunc main() {}\n")
	writeTestFile(t, dirA, "go.mod", "module example.com/scan-a\n\ngo 1.21\n")

	// Directory B: byte-identical to A except for a .honeybadgerignore that
	// suppresses the cap-no-skill-md finding.
	dirB := t.TempDir()
	writeTestFile(t, dirB, "main.go", "package main\n\nfunc main() {}\n")
	writeTestFile(t, dirB, "go.mod", "module example.com/scan-b\n\ngo 1.21\n")
	writeTestFile(t, dirB, ".honeybadgerignore", "cap-no-skill-md\n")

	scanA := callScan(t, c, ctx, dirA, "family")
	scanB := callScan(t, c, ctx, dirB, "family")

	totalA := sumFindingCounts(scanA.resultMap)
	totalB := sumFindingCounts(scanB.resultMap)
	if totalA < 0 || totalB < 0 {
		t.Fatalf("finding_counts missing or malformed: A=%v B=%v",
			scanA.resultMap["finding_counts"], scanB.resultMap["finding_counts"])
	}

	// The suppressed finding must be present in A for the difference to mean
	// anything. cap-no-skill-md is INFO, so A must report at least one finding.
	if totalA == 0 {
		t.Fatalf("expected at least one finding in A (cap-no-skill-md INFO), got 0")
	}

	// Suppression must reduce the total finding count in B relative to A.
	if totalB >= totalA {
		t.Errorf("expected .honeybadgerignore to reduce findings: B total=%d not < A total=%d", totalB, totalA)
	}

	// B's verdict must not be worse than A's after suppression.
	if verdictRank(scanB.verdict) > verdictRank(scanA.verdict) {
		t.Errorf("expected B verdict %q to be not worse than A verdict %q", scanB.verdict, scanA.verdict)
	}
}

// mcpScanResult holds the parsed output of one in-process honeybadger_scan call.
type mcpScanResult struct {
	verdict   string
	resultMap map[string]any
}

// callScan invokes honeybadger_scan on a local repo directory and parses the
// JSON result, failing the test on a protocol or tool error.
func callScan(t *testing.T, c *mcpclient.Client, ctx context.Context, dir, paranoia string) mcpScanResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = "honeybadger_scan"
	req.Params.Arguments = map[string]any{
		"repo_url": dir,
		"paranoia": paranoia,
	}
	result, err := c.CallTool(ctx, req)
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
	return mcpScanResult{verdict: verdict, resultMap: resultMap}
}

// sumFindingCounts returns the total finding count across severities from a
// parsed result's "finding_counts" map, or -1 if the field is absent/malformed.
func sumFindingCounts(resultMap map[string]any) int {
	counts, ok := resultMap["finding_counts"].(map[string]any)
	if !ok {
		return -1
	}
	total := 0
	for _, v := range counts {
		if n, ok := v.(float64); ok {
			total += int(n)
		}
	}
	return total
}

// verdictRank orders PASS < WARN < FAIL; a higher rank is a worse verdict.
func verdictRank(v string) int {
	switch v {
	case "PASS":
		return 0
	case "WARN":
		return 1
	case "FAIL":
		return 2
	default:
		return -1
	}
}

// writeTestFile creates a file in the given directory for testing.
func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("writing test file %s: %v", name, err)
	}
}
