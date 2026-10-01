package report

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestSarifZeroFindings(t *testing.T) {
	var buf bytes.Buffer
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	emitter := NewSarifEmitter(&buf, "0.0.0", rs)

	// Emit empty slice
	if err := emitter.Emit([]scan.Finding{}); err != nil {
		t.Fatalf("Failed to emit empty findings: %v", err)
	}

	// Close to finalize the document
	if err := emitter.Close(); err != nil {
		t.Fatalf("Failed to close emitter: %v", err)
	}

	// Parse the result to validate it's valid SARIF
	var result SarifLog
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal SARIF: %v", err)
	}

	// Validate that we have exactly one valid SARIF document
	// with results:[] for zero findings
	if len(result.Runs) == 0 {
		t.Error("Expected at least one run")
		return
	}
	
	// Ensure results is an empty slice, not null
	if result.Runs[0].Results == nil {
		t.Error("Expected results to be an empty slice, not nil")
	}

	// Validate that results is an empty slice
	if len(result.Runs[0].Results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(result.Runs[0].Results))
	}
}

func TestSarifSingleFinding(t *testing.T) {
	var buf bytes.Buffer
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	emitter := NewSarifEmitter(&buf, "0.0.0", rs)

	// Create a single finding
	finding := scan.Finding{
		Type:       "secret",
		Severity:   scan.SevHigh,
		RuleID:     "test-rule-123",
		Message:   "Test finding",
		File:      "test.go",
		Line:      10,
	}

	// Emit the finding
	if err := emitter.Emit(finding); err != nil {
		t.Fatalf("Failed to emit finding: %v", err)
	}

	// Close to finalize the document
	if err := emitter.Close(); err != nil {
		t.Fatalf("Failed to close emitter: %v", err)
	}

	// Parse the result
	var result SarifLog
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal SARIF: %v", err)
	}

	// Validate single result with correct level
	if len(result.Runs) == 0 {
		t.Error("Expected at least one run")
		return
	}

	if len(result.Runs[0].Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result.Runs[0].Results))
	}

	res := result.Runs[0].Results[0]
	if res.Level != "error" {
		t.Errorf("Expected level 'error', got '%s'", res.Level)
	}
	if res.RuleId != "test-rule-123" {
		t.Errorf("Expected ruleId 'test-rule-123', got '%s'", res.RuleId)
	}
}

func TestSarifMultipleFindings(t *testing.T) {
	var buf bytes.Buffer
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	emitter := NewSarifEmitter(&buf, "0.0.0", rs)

	// Create multiple findings with different severities
	findings := []scan.Finding{
		{
			Type:       "secret",
			Severity:   scan.SevHigh,
			RuleID:     "test-rule-123",
			Message:   "High severity finding",
			File:      "test.go",
			Line:      10,
		},
		{
			Type:       "cve",
			Severity:   scan.SevMedium,
			RuleID:     "test-rule-456",
			Message:   "Medium severity finding",
			File:      "main.go",
			Line:      20,
		},
		{
			Type:       "supplychain",
			Severity:   scan.SevLow,
			RuleID:     "test-rule-789",
			Message:   "Low severity finding",
			File:      "utils.go",
			Line:      30,
		},
	}

	// Emit all findings
	if err := emitter.Emit(findings); err != nil {
		t.Fatalf("Failed to emit findings: %v", err)
	}

	// Close to finalize the document
	if err := emitter.Close(); err != nil {
		t.Fatalf("Failed to close emitter: %v", err)
	}

	// Parse the result
	var result SarifLog
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal SARIF: %v", err)
	}

	// Validate 3 results with correct levels
	if len(result.Runs) == 0 {
		t.Error("Expected at least one run")
		return
	}

	if len(result.Runs[0].Results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(result.Runs[0].Results))
	}

	// Check levels
	results := result.Runs[0].Results
	if results[0].Level != "error" {
		t.Errorf("Expected first result level 'error', got '%s'", results[0].Level)
	}
	if results[1].Level != "warning" {
		t.Errorf("Expected second result level 'warning', got '%s'", results[1].Level)
	}
	if results[2].Level != "note" {
		t.Errorf("Expected third result level 'note', got '%s'", results[2].Level)
	}
}

func TestSarifSingleDocument(t *testing.T) {
	var buf bytes.Buffer
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	emitter := NewSarifEmitter(&buf, "0.0.0", rs)

	// Emit findings one by one
	finding1 := scan.Finding{
		Type:       "secret",
		Severity:   scan.SevHigh,
		RuleID:     "test-rule-123",
		Message:   "First finding",
		File:      "test.go",
		Line:      10,
	}
	
	finding2 := scan.Finding{
		Type:       "cve",
		Severity:   scan.SevMedium,
		RuleID:     "test-rule-456",
		Message:   "Second finding",
		File:      "main.go",
		Line:      20,
	}

	// Emit each individually
	if err := emitter.Emit(finding1); err != nil {
		t.Fatalf("Failed to emit first finding: %v", err)
	}
	if err := emitter.Emit(finding2); err != nil {
		t.Fatalf("Failed to emit second finding: %v", err)
	}

	// Close to finalize the document
	if err := emitter.Close(); err != nil {
		t.Fatalf("Failed to close emitter: %v", err)
	}

	// Verify we get exactly one JSON document by trying to decode it
	decoder := json.NewDecoder(&buf)
	
	// Decode first document
	var firstDoc SarifLog
	if err := decoder.Decode(&firstDoc); err != nil {
		t.Fatalf("Failed to decode first document: %v", err)
	}
	// Try to decode a second document - should get EOF
	if err := decoder.Decode(&firstDoc); err != io.EOF {
		t.Errorf("Expected EOF after first document, got: %v", err)
	}
}

func TestSarifSliceInput(t *testing.T) {
	var buf bytes.Buffer
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	emitter := NewSarifEmitter(&buf, "0.0.0", rs)

	// Create multiple findings
	findings := []scan.Finding{
		{
			Type:       "secret",
			Severity:   scan.SevHigh,
			RuleID:     "test-rule-123",
			Message:   "First finding",
			File:      "test.go",
			Line:      10,
		},
		{
			Type:       "cve",
			Severity:   scan.SevMedium,
			RuleID:     "test-rule-456",
			Message:   "Second finding",
			File:      "main.go",
			Line:      20,
		},
		{
			Type:       "supplychain",
			Severity:   scan.SevLow,
			RuleID:     "test-rule-789",
			Message:   "Third finding",
			File:      "utils.go",
			Line:      30,
		},
	}

	// Emit all findings in one call
	if err := emitter.Emit(findings); err != nil {
		t.Fatalf("Failed to emit findings slice: %v", err)
	}

	// Close to finalize the document
	if err := emitter.Close(); err != nil {
		t.Fatalf("Failed to close emitter: %v", err)
	}

	// Parse the result
	var result SarifLog
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal SARIF: %v", err)
	}

	// Validate 3 results
	if len(result.Runs) == 0 {
		t.Error("Expected at least one run")
		return
	}

	if len(result.Runs[0].Results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(result.Runs[0].Results))
	}
}