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
	// Deduplicate scannerNames while preserving order
	seen := make(map[string]bool)
	uniqueNames := make([]string, 0)
	for _, name := range scannerNames {
		if !seen[name] {
			seen[name] = true
			uniqueNames = append(uniqueNames, name)
		}
	}
	
	// Seed results with PASS for each scanner name
	results := make([]CheckResult, 0, len(uniqueNames))
	for _, name := range uniqueNames {
		results = append(results, CheckResult{
			Name: name,
			Verdict: "PASS",
			Error: "",
		})
	}
	
	// Process runtime errors
	for _, err := range runtimeErrors {
		// Look for existing entry with matching name
		found := false
		for i, result := range results {
			if result.Name == err.Scanner {
				results[i] = CheckResult{
					Name: result.Name,
					Verdict: "FAIL",
					Error: err.Message,
				}
				found = true
				break
			}
		}
		
		// If no existing entry, add new entry
		if !found {
			results = append(results, CheckResult{
				Name: err.Scanner,
				Verdict: "FAIL",
				Error: err.Message,
			})
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
// NOTE: must stay in sync with BuildScannerList (engine.go).
func BuildScannerNames(scanOpts scan.Options) []string {
	switch scanOpts.Paranoia {
	case scan.ParanoiaOff:
		return nil
	case scan.ParanoiaMinimal:
		return []string{"secrets", "cve"}
	case scan.ParanoiaFamily:
		return []string{"secrets", "cve", "supplychain", "meta", "capability", "skillsafety", "mcptool"}
	case scan.ParanoiaStrict, scan.ParanoiaParanoid:
		return []string{"secrets", "cve", "supplychain", "meta", "capability", "skillsafety", "attestation", "mcptool"}
	default:
		// Default to family
		return []string{"secrets", "cve", "supplychain", "meta", "capability", "skillsafety", "mcptool"}
	}
}