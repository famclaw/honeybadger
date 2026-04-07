package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
)

func TestNDJSONEmitFinding(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	f := scan.Finding{
		Type:     "finding",
		Severity: scan.SevHigh,
		Check:    "secrets",
		File:     "config.go",
		Line:     42,
		Message:  "hardcoded API key",
	}
	if err := e.Emit(f); err != nil {
		t.Fatalf("Emit error: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
	}
	if got["type"] != "finding" {
		t.Errorf("expected type=finding, got %v", got["type"])
	}
	if got["severity"] != "HIGH" {
		t.Errorf("expected severity=HIGH, got %v", got["severity"])
	}
}

func TestNDJSONEmitFindingWithRuleMetadata(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	f := scan.Finding{
		Type:        "finding",
		Severity:    scan.SevHigh,
		Check:       "supplychain",
		RuleID:      "sc-curl-bash",
		MoreInfoURL: "https://example.com/sc-curl-bash",
		References:  []string{"https://ref.example.com/1", "https://ref.example.com/2"},
		File:        "install.sh",
		Line:        5,
		Message:     "Downloads and executes remote script",
	}
	if err := e.Emit(f); err != nil {
		t.Fatalf("Emit error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
	}
	if got["rule_id"] != "sc-curl-bash" {
		t.Errorf("expected rule_id=sc-curl-bash, got %v", got["rule_id"])
	}
	if got["more_info_url"] != "https://example.com/sc-curl-bash" {
		t.Errorf("expected more_info_url, got %v", got["more_info_url"])
	}
	refs, ok := got["references"].([]any)
	if !ok || len(refs) != 2 {
		t.Errorf("expected references array with 2 entries, got %v", got["references"])
	}
}

func TestNDJSONEmitMultipleLines(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	events := []scan.Finding{
		{Type: "finding", Severity: scan.SevLow, Check: "meta", Message: "first"},
		{Type: "cve", Severity: scan.SevCritical, Check: "cve", Message: "second"},
		{Type: "finding", Severity: scan.SevMedium, Check: "secrets", Message: "third"},
	}
	for _, ev := range events {
		if err := e.Emit(ev); err != nil {
			t.Fatalf("Emit error: %v", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestNDJSONEmitConcurrent(t *testing.T) {
	var buf bytes.Buffer
	e := NewNDJSONEmitter(&buf)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_ = e.Emit(scan.Finding{
				Type:    "finding",
				Check:   "test",
				Message: strings.Repeat("x", 50),
			})
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d lines, got %d", n, len(lines))
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d corrupted: %v\nline: %s", i, err, line)
		}
	}
}
