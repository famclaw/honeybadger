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

func TestNewCheckResultsFromErrors(t *testing.T) {
	// Test case 1: Unknown scanner error should create new entry
	scannerNames := []string{"secrets", "cve"}
	runtimeErrors := []scan.RuntimeError{
		{
			Scanner: "runner",
			Message: "boom",
		},
	}
	
	checkResults := NewCheckResultsFromErrors(scannerNames, runtimeErrors)
	
	// Should have 3 entries: secrets PASS, cve PASS, runner FAIL
	if len(checkResults.Results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(checkResults.Results))
	}
	
	// Check that secrets and cve are PASS
	secretsPass := false
	cvePass := false
	runnerFail := false
	
	for _, result := range checkResults.Results {
		if result.Name == "secrets" && result.Verdict == "PASS" {
			secretsPass = true
		}
		if result.Name == "cve" && result.Verdict == "PASS" {
			cvePass = true
		}
		if result.Name == "runner" && result.Verdict == "FAIL" && result.Error == "boom" {
			runnerFail = true
		}
	}
	
	if !secretsPass {
		t.Error("Expected secrets scanner to be PASS")
	}
	if !cvePass {
		t.Error("Expected cve scanner to be PASS")
	}
	if !runnerFail {
		t.Error("Expected runner scanner to be FAIL with correct error")
	}
	
	// Test case 2: Known scanner error should update existing entry
	scannerNames = []string{"secrets", "cve"}
	runtimeErrors = []scan.RuntimeError{
		{
			Scanner: "cve",
			Message: "db down",
		},
	}
	
	checkResults = NewCheckResultsFromErrors(scannerNames, runtimeErrors)
	
	// Should have 2 entries: secrets PASS, cve FAIL
	if len(checkResults.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(checkResults.Results))
	}
	
	// Check that cve is FAIL with correct error
	cveFail := false
	for _, result := range checkResults.Results {
		if result.Name == "cve" && result.Verdict == "FAIL" && result.Error == "db down" {
			cveFail = true
		}
	}
	
	if !cveFail {
		t.Error("Expected cve scanner to be FAIL with correct error")
	}
}

func TestBuildScannerNames(t *testing.T) {
	// Test each paranoia level
	tests := []struct {
		paranoia scan.ParanoiaLevel
		expected []string
	}{
		{scan.ParanoiaOff, nil},
		{scan.ParanoiaMinimal, []string{"secrets", "cve"}},
		{scan.ParanoiaFamily, []string{"secrets", "cve", "supplychain", "meta", "capability", "skillsafety", "mcptool"}},
		{scan.ParanoiaStrict, []string{"secrets", "cve", "supplychain", "meta", "capability", "skillsafety", "attestation", "mcptool"}},
		{scan.ParanoiaParanoid, []string{"secrets", "cve", "supplychain", "meta", "capability", "skillsafety", "attestation", "mcptool"}},
	}
	
	for _, tc := range tests {
		opts := scan.Options{Paranoia: tc.paranoia}
		result := BuildScannerNames(opts)
		
		// Check length
		if len(result) != len(tc.expected) {
			t.Errorf("For paranoia %v: expected length %d, got %d", tc.paranoia, len(tc.expected), len(result))
		}
		
		// Check elements
		for i, expected := range tc.expected {
			if result[i] != expected {
				t.Errorf("For paranoia %v: expected[%d] = %s, got %s", tc.paranoia, i, expected, result[i])
			}
		}
	}
}