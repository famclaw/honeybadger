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
		"finding_counts": map[string]any{
			"critical": 0,
			"high":     1,
			"medium":   2,
			"low":      0,
		},
		"cve_count":        3,
		"cve_max_severity": "HIGH",
		"duration_ms":      1234,
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

// Regression: TextEmitter was reading m["counts"] but main.go emits m["finding_counts"].
func TestTextEmitter_VerdictFindingCounts(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":    "result",
		"verdict": "FAIL",
		"finding_counts": map[string]any{
			"critical": 1,
			"high":     2,
			"medium":   0,
			"low":      3,
		},
		"cve_count":   0,
		"duration_ms": 500,
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "1 critical") {
		t.Errorf("expected '1 critical' in output, got: %s", out)
	}
	if !strings.Contains(out, "2 high") {
		t.Errorf("expected '2 high' in output, got: %s", out)
	}
	if !strings.Contains(out, "3 low") {
		t.Errorf("expected '3 low' in output, got: %s", out)
	}
	// Verify counts are NOT all zero (the bug produced "0 critical, 0 high, 0 medium, 0 low").
	if strings.Contains(out, "0 critical, 0 high, 0 medium, 0 low") {
		t.Errorf("finding counts are all zero — regression: emitter not reading finding_counts key")
	}
}

// Regression: TextEmitter was reading m["cves"] but main.go emits m["cve_count"] / m["cve_max_severity"].
func TestTextEmitter_VerdictCVECounts(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":    "result",
		"verdict": "WARN",
		"finding_counts": map[string]any{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		},
		"cve_count":        3,
		"cve_max_severity": "HIGH",
		"duration_ms":      100,
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CVEs: 3") {
		t.Errorf("expected 'CVEs: 3' in output, got: %s", out)
	}
	if !strings.Contains(out, "max severity: HIGH") {
		t.Errorf("expected 'max severity: HIGH' in output, got: %s", out)
	}
	// Verify CVE count is NOT zero (the bug produced "CVEs: 0").
	if strings.Contains(out, "CVEs: 0") {
		t.Errorf("CVE count is zero — regression: emitter not reading cve_count key")
	}
}

// Regression: sandbox events were rendered as [info] instead of [sandbox].
func TestTextEmitter_SandboxEvent(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":               "sandbox",
		"available":          true,
		"reason":             "docker",
		"effective_paranoia": "strict",
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[sandbox]") {
		t.Errorf("expected [sandbox] prefix, got: %s", out)
	}
	if strings.Contains(out, "[info]") {
		t.Errorf("sandbox event should not use [info] prefix, got: %s", out)
	}
	if !strings.Contains(out, "Available") {
		t.Errorf("expected 'Available' in output, got: %s", out)
	}
	if !strings.Contains(out, "strict") {
		t.Errorf("expected effective paranoia 'strict' in output, got: %s", out)
	}
}

// Regression: health events were rendered as raw JSON [info] instead of structured [health].
func TestTextEmitter_HealthEvent(t *testing.T) {
	var buf bytes.Buffer
	e := NewTextEmitter(&buf)

	err := e.Emit(map[string]any{
		"type":         "health",
		"stars":        1500,
		"contributors": 42,
		"age_days":     365,
		"has_license":  true,
	})
	if err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[health]") {
		t.Errorf("expected [health] prefix, got: %s", out)
	}
	if strings.Contains(out, "[info]") {
		t.Errorf("health event should not use [info] prefix, got: %s", out)
	}
	if !strings.Contains(out, "Stars: 1500") {
		t.Errorf("expected 'Stars: 1500' in output, got: %s", out)
	}
	if !strings.Contains(out, "Contributors: 42") {
		t.Errorf("expected 'Contributors: 42' in output, got: %s", out)
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
