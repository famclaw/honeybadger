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
	s := newMCPServer()

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
	s := newMCPServer()

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
	s := newMCPServer()

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
	s := newMCPServer()

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

// writeTestFile creates a file in the given directory for testing.
func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("writing test file %s: %v", name, err)
	}
}
