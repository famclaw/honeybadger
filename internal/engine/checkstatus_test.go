package engine

import (
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/report"
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

	// Test with no errors (zero-value CheckResults{})
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

	// Test nil-safe behavior with empty slice
	emptyResults := CheckResults{
		Results: []CheckResult{},
	}
	verdict, _, _ = ComputeVerdictWithCheckStatus(findings, scan.ParanoiaFamily, nil, emptyResults)
	if verdict != "PASS" {
		t.Errorf("Expected PASS verdict with empty slice, got %s", verdict)
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

// TestNilAndEmptyResultsEquivalent asserts that a zero-value CheckResults{}
// (nil Results) and an explicitly empty slice take the same code path in
// ComputeVerdictWithCheckStatus: neither downgrades the verdict.
func TestNilAndEmptyResultsEquivalent(t *testing.T) {
	findings := []scan.Finding{}

	vNil, _, _ := ComputeVerdictWithCheckStatus(findings, scan.ParanoiaFamily, nil, CheckResults{})

	vEmpty, _, _ := ComputeVerdictWithCheckStatus(findings, scan.ParanoiaFamily, nil,
		CheckResults{Results: []CheckResult{}})

	if vNil != "PASS" {
		t.Errorf("nil Results: expected PASS, got %s", vNil)
	}
	if vEmpty != "PASS" {
		t.Errorf("empty Results: expected PASS, got %s", vEmpty)
	}
	if vNil != vEmpty {
		t.Errorf("nil and empty Results must produce the same verdict: %q vs %q", vNil, vEmpty)
	}
}

// TestUnknownScannerTriggersIncomplete asserts the documented fail-safe:
// a RuntimeError naming a scanner outside the expected set appends a FAIL
// entry, and feeding that into ComputeVerdictWithCheckStatus downgrades an
// otherwise clean verdict to INCOMPLETE.
func TestUnknownScannerTriggersIncomplete(t *testing.T) {
	scannerNames := []string{"secrets", "cve"}
	runtimeErrors := []scan.RuntimeError{{Scanner: "rogue", Message: "dispatch bug"}}

	cr := NewCheckResultsFromErrors(scannerNames, runtimeErrors)

	var foundFail bool
	for _, r := range cr.Results {
		if r.Name == "rogue" && r.Verdict == "FAIL" {
			foundFail = true
		}
	}
	if !foundFail {
		t.Fatal("expected a FAIL entry for unknown scanner 'rogue'")
	}

	verdict, reasoning, _ := ComputeVerdictWithCheckStatus(nil, scan.ParanoiaFamily, nil, cr)
	if verdict != "INCOMPLETE" {
		t.Errorf("expected INCOMPLETE, got %s (reasoning: %s)", verdict, reasoning)
	}
}

// TestNoDoubleLLMApplication guards against re-applying the LLM worse-of
// escalation in ComputeVerdictWithCheckStatus. ComputeVerdict already
// escalates WARN to the LLM's FAIL; the check-status layer must not alter
// that result a second time. The LLM reasoning must appear exactly once.
func TestNoDoubleLLMApplication(t *testing.T) {
	// MEDIUM at family is one level below the HIGH threshold -> WARN base.
	findings := []scan.Finding{{Type: "finding", Severity: scan.SevMedium, Check: "meta", Message: "medium"}}
	llm := &report.LLMVerdict{Verdict: "FAIL", Reasoning: "llm-escalated"}
	cr := CheckResults{Results: []CheckResult{{Name: "secrets", Verdict: "PASS"}}}

	verdict, reasoning, _ := ComputeVerdictWithCheckStatus(findings, scan.ParanoiaFamily, llm, cr)

	if verdict != "FAIL" {
		t.Errorf("expected FAIL, got %s (reasoning: %s)", verdict, reasoning)
	}
	if strings.Count(reasoning, "llm-escalated") != 1 {
		t.Errorf("reasoning mentions LLM verdict %d times, want 1: %q",
			strings.Count(reasoning, "llm-escalated"), reasoning)
	}
}

// TestBuildScannerNamesMatchesList asserts that BuildScannerNames and
// BuildScannerList agree on the scanner count for every paranoia tier,
// i.e. both derive from the same shared source (scannersFor) and cannot
// silently drift apart.
func TestBuildScannerNamesMatchesList(t *testing.T) {
	tiers := []scan.ParanoiaLevel{
		scan.ParanoiaOff, scan.ParanoiaMinimal, scan.ParanoiaFamily,
		scan.ParanoiaStrict, scan.ParanoiaParanoid,
	}
	for _, p := range tiers {
		opts := scan.Options{Paranoia: p}
		names := BuildScannerNames(opts)
		fns := BuildScannerList(opts)
		if len(names) != len(fns) {
			t.Errorf("paranoia=%s: BuildScannerNames len %d != BuildScannerList len %d",
				p, len(names), len(fns))
		}
	}
}
