package engine

import (
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
	"log"
)

// CheckResult represents the result of a single check
type CheckResult struct {
	Name    string
	Verdict string
	Error   string
}

// CheckResults represents the collection of all check results
//
// Note: CheckResults must be constructed via NewCheckResultsFromErrors as the sole constructor.
// A zero-value CheckResults{} means "no checks tracked" and will NOT downgrade the verdict.
// Callers with runtime errors that were NOT passed through NewCheckResultsFromErrors
// get no protection from this mechanism.
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
			Name:    name,
			Verdict: "PASS",
			Error:   "",
		})
	}

	// Process runtime errors
	for _, err := range runtimeErrors {
		// Look for existing entry with matching name
		found := false
		for i, result := range results {
			if result.Name == err.Scanner {
				results[i] = CheckResult{
					Name:    result.Name,
					Verdict: "FAIL",
					Error:   err.Message,
				}
				found = true
				break
			}
		}

		// If no existing entry, add new entry
		if !found {
			// unknown scanner names (e.g. "runner", which is how scanner panics are tagged by scan.RunAll)
			// MUST produce a FAIL entry so a panicked/misrouted scanner can never yield an unqualified PASS;
			// a misrouted or spurious error degrading the verdict to INCOMPLETE is the desired fail-safe direction
			// for a security scanner.
			log.Printf("honeybadger: runtime error from unrecognized scanner %q: %s — counting as failed check (fail-safe)", err.Scanner, err.Message)
			results = append(results, CheckResult{
				Name:    err.Scanner,
				Verdict: "FAIL",
				Error:   err.Message,
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
	// ComputeVerdict already applies the LLM worse-of escalation internally;
	// do not re-apply it here (see engine.go ComputeVerdict, "Combine with LLM verdict").
	baseVerdict, reasoning, keyFinding := ComputeVerdict(findings, paranoia, llmVerdict)

	// If any tracked check failed, downgrade PASS/WARN to INCOMPLETE.
	// A nil or empty Results slice means no checks were tracked (zero-value
	// CheckResults{} or an explicitly empty slice), so there is nothing to
	// evaluate and we skip the block entirely.
	if len(checkResults.Results) > 0 {
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

	return baseVerdict, reasoning, keyFinding
}

// BuildScannerNames returns the list of all scanner names
// NOTE: must stay in sync with BuildScannerList (engine.go).
func BuildScannerNames(scanOpts scan.Options) []string {
	out := make([]string, 0)
	for _, s := range scannersFor(scanOpts) {
		out = append(out, s.Name)
	}
	return out
}
