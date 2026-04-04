package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestTextEmitFinding(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":     "finding",
		"severity": "HIGH",
		"file":     "main.go",
		"line":     10,
		"message":  "hardcoded secret",
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[HIGH]") {
		t.Errorf("expected severity marker [HIGH], got: %s", out)
	}
	if !strings.Contains(out, "main.go:10") {
		t.Errorf("expected file:line, got: %s", out)
	}
	if !strings.Contains(out, "hardcoded secret") {
		t.Errorf("expected message, got: %s", out)
	}
}

func TestTextEmitResult(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":      "result",
		"verdict":   "WARN",
		"reasoning": "Some suspicious network calls detected.",
		"counts": map[string]any{
			"critical": 0,
			"high":     1,
			"medium":   2,
			"low":      0,
		},
		"cves": map[string]any{
			"count":        3,
			"max_severity": "HIGH",
		},
		"duration_ms": 1234,
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "VERDICT: WARN") {
		t.Errorf("expected VERDICT: WARN, got: %s", out)
	}
	if !strings.Contains(out, "══════") {
		t.Errorf("expected border, got: %s", out)
	}
	if !strings.Contains(out, "1 high") {
		t.Errorf("expected finding counts, got: %s", out)
	}
	if !strings.Contains(out, "CVEs: 3") {
		t.Errorf("expected CVE count, got: %s", out)
	}
	if !strings.Contains(out, "Duration: 1234ms") {
		t.Errorf("expected duration, got: %s", out)
	}
}

func TestTextEmitProgress(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":    "progress",
		"message": "scanning dependencies",
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[*]") {
		t.Errorf("expected [*] prefix, got: %s", out)
	}
	if !strings.Contains(out, "scanning dependencies") {
		t.Errorf("expected message, got: %s", out)
	}
}
