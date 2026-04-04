package report

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestAssembleLLMPromptContainsExpectedFields(t *testing.T) {
	repo := &fetch.Repo{
		URL:   "https://github.com/example/plugin",
		SHA:   "abc123",
		Files: map[string][]byte{
			"go.mod":   []byte("module example\ngo 1.21\n"),
			"main.go":  []byte("package main\nfunc main() {}\n"),
			"other.go": []byte("package other\n"),
		},
		Health: fetch.Health{
			Stars:        100,
			Contributors: 5,
			AgeDays:      365,
		},
	}
	findings := []scan.Finding{
		{Type: "finding", Severity: scan.SevHigh, Check: "secrets", File: "main.go", Line: 5, Message: "leaked key"},
	}
	opts := LLMOptions{
		Paranoia: "family",
		Platform: "github",
		Tier:     "free",
		ToolsRan: []string{"secrets", "cve"},
	}

	prompt := AssembleLLMPrompt(repo, findings, opts)

	// Verify it includes key fields
	if !strings.Contains(prompt, "https://github.com/example/plugin") {
		t.Error("prompt missing repo URL")
	}
	if !strings.Contains(prompt, "family") {
		t.Error("prompt missing paranoia level")
	}
	if !strings.Contains(prompt, "leaked key") {
		t.Error("prompt missing finding message")
	}
	if !strings.Contains(prompt, "abc123") {
		t.Error("prompt missing SHA")
	}

	// Verify under budget
	tokenEstimate := len(prompt) / charsPerToken
	if tokenEstimate > maxTokenBudget {
		t.Errorf("prompt exceeds token budget: estimated %d tokens (max %d)", tokenEstimate, maxTokenBudget)
	}
}

func TestAssembleLLMPromptPriorityOrdering(t *testing.T) {
	repo := &fetch.Repo{
		URL: "https://github.com/example/plugin",
		SHA: "abc123",
		Files: map[string][]byte{
			"go.mod":       []byte("module example\ngo 1.21\n"),
			"main.go":      []byte("package main\nfunc main() {}\n"),
			"utils/foo.go": []byte("package utils\n"),
			"Makefile":     []byte("build:\n\tgo build\n"),
		},
		Health: fetch.Health{},
	}

	prompt := AssembleLLMPrompt(repo, nil, LLMOptions{Paranoia: "family"})

	// go.mod (priority 1) should appear before main.go (priority 4)
	goModIdx := strings.Index(prompt, "=== go.mod ===")
	mainIdx := strings.Index(prompt, "=== main.go ===")
	if goModIdx == -1 {
		t.Fatal("go.mod not found in prompt")
	}
	if mainIdx == -1 {
		t.Fatal("main.go not found in prompt")
	}
	if goModIdx > mainIdx {
		t.Error("go.mod should appear before main.go (dependency files have higher priority)")
	}

	// Makefile (priority 2) should appear before main.go (priority 4)
	makeIdx := strings.Index(prompt, "=== Makefile ===")
	if makeIdx == -1 {
		t.Fatal("Makefile not found in prompt")
	}
	if makeIdx > mainIdx {
		t.Error("Makefile should appear before main.go (build scripts have higher priority)")
	}
}

func TestCallLLMWithMock(t *testing.T) {
	cannedResp := map[string]any{
		"choices": []map[string]any{
			{
				"message": map[string]string{
					"content": `{"verdict":"WARN","reasoning":"suspicious outbound call","key_finding":"net/http dial in init()"}`,
				},
			},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cannedResp)
	}))
	defer server.Close()

	verdict, err := CallLLM(context.Background(), "test prompt", server.URL, "", "test-model")
	if err != nil {
		t.Fatalf("CallLLM error: %v", err)
	}
	if verdict == nil {
		t.Fatal("expected non-nil verdict")
	}
	if verdict.Verdict != "WARN" {
		t.Errorf("expected WARN, got %s", verdict.Verdict)
	}
	if verdict.Reasoning != "suspicious outbound call" {
		t.Errorf("unexpected reasoning: %s", verdict.Reasoning)
	}
	if verdict.KeyFinding != "net/http dial in init()" {
		t.Errorf("unexpected key_finding: %s", verdict.KeyFinding)
	}
}

func TestCallLLMEmptyEndpoint(t *testing.T) {
	verdict, err := CallLLM(context.Background(), "prompt", "", "", "model")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if verdict != nil {
		t.Errorf("expected nil verdict for empty endpoint, got: %+v", verdict)
	}
}

func TestCallLLMWithAuth(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		cannedResp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": `{"verdict":"PASS","reasoning":"ok","key_finding":null}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cannedResp)
	}))
	defer server.Close()

	_, err := CallLLM(context.Background(), "test", server.URL, "sk-test-key", "model")
	if err != nil {
		t.Fatalf("CallLLM error: %v", err)
	}
	if gotAuth != "Bearer sk-test-key" {
		t.Errorf("expected Authorization header 'Bearer sk-test-key', got '%s'", gotAuth)
	}
}
