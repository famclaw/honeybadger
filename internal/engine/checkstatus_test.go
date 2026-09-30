package engine

import (
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
)

func TestCheckStatus(t *testing.T) {
	// Test NewCheckResultsFromErrors
	scannerNames := []string{"secrets", "cve", "capability"}
	runtimeErrors := []scan.RuntimeError{
		{
			Scanner: "cve",
			Message: "failed to run cve scanner",
		},
	}
	
	checkResults := NewCheckResultsFromErrors(scannerNames, runtimeErrors)
	
	if len(checkResults.Results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(checkResults.Results))
	}
	
	// Check that cve is marked as failed
	foundFailed := false
	for _, result := range checkResults.Results {
		if result.Name == "cve" && result.Verdict == "FAIL" {
			foundFailed = true
			break
		}
	}
	
	if !foundFailed {
		t.Error("Expected cve scanner to be marked as failed")
	}
	
	// Test ComputeVerdictWithCheckStatus
	findings := []scan.Finding{}
	
	// Test with no errors
	verdict, _, _ := ComputeVerdictWithCheckStatus(findings, scan.ParanoiaFamily, nil, CheckResults{})
	if verdict != "PASS" {
		t.Errorf("Expected PASS verdict, got %s", verdict)
	}
	
	// Test with failed check
	checkResultsWithFail := CheckResults{
		Results: []CheckResult{
			{Name: "secrets", Verdict: "PASS"},
			{Name: "cve", Verdict: "FAIL"},
		},
	}
	
	verdict, _, _ = ComputeVerdictWithCheckStatus(findings, scan.ParanoiaFamily, nil, checkResultsWithFail)
	if verdict != "INCOMPLETE" {
		t.Errorf("Expected INCOMPLETE verdict, got %s", verdict)
	}
}