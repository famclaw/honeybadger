package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write first entry
	result1 := map[string]any{
		"type":    "result",
		"verdict": "PASS",
	}
	if err := WriteAudit(path, result1); err != nil {
		t.Fatalf("WriteAudit #1: %v", err)
	}

	// Write second entry
	result2 := map[string]any{
		"type":    "result",
		"verdict": "FAIL",
	}
	if err := WriteAudit(path, result2); err != nil {
		t.Fatalf("WriteAudit #2: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := splitNonEmpty(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), string(data))
	}

	var m1, m2 map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m1); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &m2); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}

	if m1["verdict"] != "PASS" {
		t.Errorf("line 1 verdict = %v, want PASS", m1["verdict"])
	}
	if m2["verdict"] != "FAIL" {
		t.Errorf("line 2 verdict = %v, want FAIL", m2["verdict"])
	}
}

func TestWriteAuditCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "audit.jsonl")

	// Should fail because subdir doesn't exist
	err := WriteAudit(path, map[string]any{"test": true})
	if err == nil {
		t.Error("expected error when directory doesn't exist")
	}
}

func splitNonEmpty(s string) []string {
	var result []string
	for _, line := range splitLines(s) {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
