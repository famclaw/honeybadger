package mcptool

import "testing"

func btrue() *bool { b := true; return &b }

func TestCapabilityUnannotated(t *testing.T) {
	tools := []ToolDef{{Name: "t", Description: "does things"}}
	fs := detectCapability(tools, nil)
	f := hasRule(fs, "mcp-tool-unannotated")
	if f == nil || f.Severity != "LOW" {
		t.Fatalf("expected LOW unannotated finding, got %+v", f)
	}
}

func TestCapabilityMismatchVerb(t *testing.T) {
	tools := []ToolDef{{
		Name: "fetch_data", Description: "Write the result to disk and upload it.",
		Annotations: &Annotations{ReadOnlyHint: btrue()},
	}}
	fs := detectCapability(tools, nil)
	f := hasRule(fs, "mcp-capability-mismatch")
	if f == nil || f.Severity != "MEDIUM" {
		t.Fatalf("expected MEDIUM mismatch finding, got %+v", f)
	}
}

func TestCapabilityMismatchParam(t *testing.T) {
	tools := []ToolDef{{
		Name: "get_status", Description: "Get status.",
		Annotations: &Annotations{ReadOnlyHint: btrue()},
		Params:      []ParamDef{{Name: "payload", Type: "string"}},
	}}
	fs := detectCapability(tools, nil)
	if hasRule(fs, "mcp-capability-mismatch") == nil {
		t.Fatalf("expected mismatch on write-payload param, got %+v", fs)
	}
}

func TestCapabilityCleanReadOnly(t *testing.T) {
	tools := []ToolDef{{
		Name: "read_status", Description: "Return the current status value.",
		Annotations: &Annotations{ReadOnlyHint: btrue()},
		Params:      []ParamDef{{Name: "id", Type: "string"}},
	}}
	fs := detectCapability(tools, nil)
	if hasRule(fs, "mcp-capability-mismatch") != nil {
		t.Fatalf("clean read-only tool flagged: %+v", fs)
	}
}

func TestCapabilityLayer4SourceEscalation(t *testing.T) {
	files := mkFiles(map[string]string{
		"tool.go": `package main
import "os"
func handler() { os.WriteFile("/tmp/x", nil, 0644) }`,
	})
	tools := []ToolDef{{
		Name: "get_thing", Description: "Get a thing.", SourceFile: "tool.go",
		Annotations: &Annotations{ReadOnlyHint: btrue()},
	}}
	fs := detectCapability(tools, files)
	f := hasRule(fs, "mcp-capability-mismatch")
	if f == nil || f.Severity != "HIGH" {
		t.Fatalf("expected HIGH source-confirmed mismatch, got %+v", f)
	}
}
