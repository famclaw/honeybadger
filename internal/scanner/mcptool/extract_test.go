package mcptool

import (
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
)

func TestExtractGoNewTool(t *testing.T) {
	src := `package main
var t = mcp.NewTool("calculate", mcp.WithDescription("Perform arithmetic"))`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"main.go": src})}
	tools := extractFromSource(repo)
	if len(tools) != 1 || tools[0].Name != "calculate" {
		t.Fatalf("NewTool not extracted: %+v", tools)
	}
	if tools[0].Description != "Perform arithmetic" {
		t.Fatalf("description not extracted: %q", tools[0].Description)
	}
	if tools[0].SourceFile != "main.go" {
		t.Fatalf("SourceFile = %q, want main.go", tools[0].SourceFile)
	}
}

func TestExtractGoStructLiteral(t *testing.T) {
	src := `package main
var t = &mcp.Tool{Name: "greet", Description: "say hi"}`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"s.go": src})}
	tools := extractFromSource(repo)
	if len(tools) != 1 || tools[0].Name != "greet" || tools[0].Description != "say hi" {
		t.Fatalf("struct literal not extracted: %+v", tools)
	}
}

func TestExtractGoRegisterTool(t *testing.T) {
	src := `package main
func init() { server.RegisterTool("hello", "Say hello", handler) }`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"r.go": src})}
	tools := extractFromSource(repo)
	if len(tools) != 1 || tools[0].Name != "hello" || tools[0].Description != "Say hello" {
		t.Fatalf("RegisterTool not extracted: %+v", tools)
	}
}

func TestExtractTSRegisterTool(t *testing.T) {
	src := `server.registerTool("calculate-bmi", { title: "BMI", description: "Calculate BMI" }, handler);`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"s.ts": src})}
	tools := extractFromSource(repo)
	if len(tools) != 1 || tools[0].Name != "calculate-bmi" || tools[0].Description != "Calculate BMI" {
		t.Fatalf("TS registerTool not extracted: %+v", tools)
	}
}

func TestExtractTSServerTool(t *testing.T) {
	src := `server.tool("read_file", "Read a file", schema, handler);`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"s.js": src})}
	tools := extractFromSource(repo)
	if len(tools) != 1 || tools[0].Name != "read_file" || tools[0].Description != "Read a file" {
		t.Fatalf("TS server.tool not extracted: %+v", tools)
	}
}

func TestExtractPythonTool(t *testing.T) {
	src := `tools = [Tool(name="git_status", description="Show status", inputSchema=s)]`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"s.py": src})}
	tools := extractFromSource(repo)
	if len(tools) != 1 || tools[0].Name != "git_status" || tools[0].Description != "Show status" {
		t.Fatalf("Python Tool() not extracted: %+v", tools)
	}
}

// TestExtractGoNewToolNoBridging ensures the regex does not span two NewTool
// calls: the first tool (no WithDescription) must NOT steal the second tool's
// description.
func TestExtractGoNewToolNoBridging(t *testing.T) {
	src := `package main
var a = mcp.NewTool("first",
	mcp.WithReadOnly())
var b = mcp.NewTool("second",
	mcp.WithDescription("Second tool description"))`
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"main.go": src})}
	tools := extractFromSource(repo)
	// "first" should not have "Second tool description"
	for _, td := range tools {
		if td.Name == "first" && td.Description == "Second tool description" {
			t.Fatalf("goNewToolRe bridged two tool declarations: first tool got second's description")
		}
	}
	// "second" should have its description
	var foundSecond bool
	for _, td := range tools {
		if td.Name == "second" && td.Description == "Second tool description" {
			foundSecond = true
		}
	}
	if !foundSecond {
		t.Fatalf("second tool's description not extracted correctly: %+v", tools)
	}
}
