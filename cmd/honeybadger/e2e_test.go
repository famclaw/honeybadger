//go:build integration

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/testfixture"
)

// jsonrpcRequest builds a JSON-RPC 2.0 request string.
func jsonrpcRequest(id int, method string, params any) string {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// jsonrpcNotification builds a JSON-RPC 2.0 notification (no id).
func jsonrpcNotification(method string, params any) string {
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// readJSONRPCResponse reads one JSON-RPC response from a scanner.
// It skips empty lines and returns the parsed response map.
func readJSONRPCResponse(t *testing.T, scanner *bufio.Scanner) map[string]any {
	t.Helper()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var resp map[string]any
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("failed to parse JSON-RPC response: %v\nline: %s", err, line)
		}
		return resp
	}
	t.Fatal("no more JSON-RPC responses")
	return nil
}

func TestE2E_StdioMCPServer(t *testing.T) {
	cmd := exec.Command(testBinary, "--mcp-server")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cmd.Process.Kill()

	scanner := bufio.NewScanner(stdout)
	// Increase scanner buffer for large responses
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	// 1. Send initialize
	initMsg := jsonrpcRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e-test", "version": "1.0"},
	})
	fmt.Fprintf(stdin, "%s\n", initMsg)

	initResp := readJSONRPCResponse(t, scanner)
	if initResp["error"] != nil {
		t.Fatalf("initialize error: %v", initResp["error"])
	}

	// Send initialized notification
	fmt.Fprintf(stdin, "%s\n", jsonrpcNotification("notifications/initialized", nil))

	// 2. Send tools/list
	fmt.Fprintf(stdin, "%s\n", jsonrpcRequest(2, "tools/list", map[string]any{}))
	toolsResp := readJSONRPCResponse(t, scanner)
	if toolsResp["error"] != nil {
		t.Fatalf("tools/list error: %v", toolsResp["error"])
	}

	toolsResult, ok := toolsResp["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list result not a map: %T", toolsResp["result"])
	}
	tools, ok := toolsResult["tools"].([]any)
	if !ok {
		t.Fatalf("tools not an array: %T", toolsResult["tools"])
	}

	foundScan := false
	for _, tool := range tools {
		toolMap, _ := tool.(map[string]any)
		if toolMap["name"] == "honeybadger_scan" {
			foundScan = true
			// Verify input schema has expected properties
			schema, _ := toolMap["inputSchema"].(map[string]any)
			props, _ := schema["properties"].(map[string]any)
			for _, prop := range []string{"repo_url", "paranoia", "installed_sha", "installed_tool_hash", "path"} {
				if _, exists := props[prop]; !exists {
					t.Errorf("missing property %q in honeybadger_scan schema", prop)
				}
			}
		}
	}
	if !foundScan {
		t.Fatal("honeybadger_scan tool not found in tools/list")
	}

	// 3. Scan clean repo -> PASS
	cleanDir := testfixture.WriteToDir(t, testfixture.CleanRepo())
	fmt.Fprintf(stdin, "%s\n", jsonrpcRequest(3, "tools/call", map[string]any{
		"name": "honeybadger_scan",
		"arguments": map[string]any{
			"repo_url": cleanDir,
			"paranoia": "family",
		},
	}))

	cleanResp := readJSONRPCResponse(t, scanner)
	if cleanResp["error"] != nil {
		t.Fatalf("clean scan error: %v", cleanResp["error"])
	}
	cleanResult := extractToolResult(t, cleanResp)
	if cleanResult["verdict"] != "PASS" {
		t.Errorf("clean repo verdict = %q, want PASS", cleanResult["verdict"])
	}
	// Verify response schema fields
	for _, field := range []string{"verdict", "reasoning", "finding_counts", "paranoia", "scanned_at", "duration_ms"} {
		if _, exists := cleanResult[field]; !exists {
			t.Errorf("clean result missing field %q", field)
		}
	}

	// 4. Scan secrets repo -> FAIL
	secretsDir := testfixture.WriteToDir(t, testfixture.SecretsRepo())
	fmt.Fprintf(stdin, "%s\n", jsonrpcRequest(4, "tools/call", map[string]any{
		"name": "honeybadger_scan",
		"arguments": map[string]any{
			"repo_url": secretsDir,
			"paranoia": "family",
		},
	}))

	secretsResp := readJSONRPCResponse(t, scanner)
	if secretsResp["error"] != nil {
		t.Fatalf("secrets scan error: %v", secretsResp["error"])
	}
	secretsResult := extractToolResult(t, secretsResp)
	if secretsResult["verdict"] != "FAIL" {
		t.Errorf("secrets repo verdict = %q, want FAIL", secretsResult["verdict"])
	}

	// 5. Error handling — empty repo_url
	fmt.Fprintf(stdin, "%s\n", jsonrpcRequest(5, "tools/call", map[string]any{
		"name":      "honeybadger_scan",
		"arguments": map[string]any{},
	}))

	errResp := readJSONRPCResponse(t, scanner)
	if errResp["error"] != nil {
		// Protocol-level error is acceptable
		t.Logf("got protocol error for empty repo_url (acceptable): %v", errResp["error"])
	} else {
		// Tool-level error: isError should be true
		errResult, _ := errResp["result"].(map[string]any)
		if errResult != nil {
			isError, _ := errResult["isError"].(bool)
			if !isError {
				t.Error("expected isError=true for empty repo_url")
			}
		}
	}

	// Close stdin to signal server to exit
	stdin.Close()
}

// extractToolResult parses the JSON text content from a tools/call response.
func extractToolResult(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result not a map: %v", resp["result"])
	}

	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("content not an array or empty: %v", result["content"])
	}

	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if text == "" {
		t.Fatal("empty text in tool result content")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("failed to parse tool result text: %v\nraw: %s", err, text)
	}
	return parsed
}
