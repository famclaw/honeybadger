package engine

import (
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
)

// CheckResult represents the result of a single check
type CheckResult struct {
	Name  string
	Verdict string
	Error string
}

// CheckResults represents the collection of all check results
type CheckResults struct {
	Results []CheckResult
}

// NewCheckResultsFromErrors creates a CheckResults from runtime errors
func NewCheckResultsFromErrors(scannerNames []string, runtimeErrors []scan.RuntimeError) CheckResults {
	results := make([]CheckResult, 0, len(scannerNames))
	
	for _, name := range scannerNames {
		results = append(results, CheckResult{
			Name: name,
			Verdict: "PASS",
			Error: "",
		})
	}
	
	// Mark any failed checks as FAIL
	for _, err := range runtimeErrors {
		for i, result := range results {
			if result.Name == err.Scanner {
				results[i] = CheckResult{
					Name: result.Name,
					Verdict: "FAIL",
					Error: err.Message,
				}
				break
			}
		}
	}
	
	return CheckResults{
		Results: results,
	}
}

// ComputeVerdictWithCheckStatus computes the verdict considering both findings and check status
func ComputeVerdictWithCheckStatus(findings []scan.Finding, paranoia scan.ParanoiaLevel, llmVerdict *report.LLMVerdict, checkResults CheckResults) (string, string, string) {
	// First compute the base verdict from findings
	baseVerdict, reasoning, keyFinding := ComputeVerdict(findings, paranoia, llmVerdict)
	
	// If we have check results, and any required check failed, downgrade PASS/WARN to INCOMPLETE
	// For simplicity, we assume all checks are required for now
	if checkResults.Results != nil {
		// Check if any required check failed
		hasFailedRequiredCheck := false
		for _, result := range checkResults.Results {
			if result.Verdict == "FAIL" {
				hasFailedRequiredCheck = true
				break
			}
		}
		
		// If a required check failed and we had PASS or WARN, downgrade to INCOMPLETE
		if hasFailedRequiredCheck && (baseVerdict == "PASS" || baseVerdict == "WARN") {
			baseVerdict = "INCOMPLETE"
			reasoning = reasoning + " (downgraded due to failed required check)"
		}
	}
	
	// Apply LLM worse-of logic
	if llmVerdict != nil {
		llmRank := VerdictRank(llmVerdict.Verdict)
		rulesRank := VerdictRank(baseVerdict)
		if llmRank > rulesRank {
			baseVerdict = llmVerdict.Verdict
			reasoning = "LLM verdict: " + llmVerdict.Reasoning
			if llmVerdict.KeyFinding != "" {
				keyFinding = llmVerdict.KeyFinding
			}
		}
	}
	
	return baseVerdict, reasoning, keyFinding
}

// BuildScannerNames returns the list of all scanner names
func BuildScannerNames(scanOpts scan.Options) []string {
	return []string{"secrets", "cve", "capability", "mcptool", "attestation", "supplychain", "meta", "skillsafety"}
}