package secrets

import (
	"context"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Run scans repository files for hardcoded secrets using gitleaks.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	// Create gitleaks detector with default config (800+ credential patterns).
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevError,
			Check:    "secrets",
			Message:  "failed to load gitleaks config: " + err.Error(),
		}
		return
	}

	// Scan each file by constructing in-memory fragments.
	for relPath, content := range repo.Files {
		select {
		case <-ctx.Done():
			return
		default:
		}

		fragment := sources.Fragment{
			Raw:      string(content),
			FilePath: relPath,
		}

		findings := detector.Detect(detect.Fragment(fragment))
		for _, f := range findings {
			converted, ok := convertFinding(f, relPath)
			if ok {
				out <- converted
			}
		}
	}
}

// convertFinding converts a gitleaks report.Finding to a HoneyBadger Finding,
// applying noise-reduction rules. Returns false if the finding should be skipped.
func convertFinding(gf report.Finding, relPath string) (scan.Finding, bool) {
	line := gf.Line
	secret := gf.Secret
	match := gf.Match

	// Skip env var references — these are correct usage, not leaks.
	if isEnvVarRef(secret) || isEnvVarRef(match) || isEnvVarRef(line) {
		return scan.Finding{}, false
	}

	// Skip placeholder values.
	if scan.IsPlaceholder(line) || scan.IsPlaceholder(secret) {
		return scan.Finding{}, false
	}

	// Map severity.
	sev := mapSeverity(gf)

	// Reduce severity for test files.
	if isTestFile(relPath) {
		sev = reduceSeverity(sev)
	}

	return scan.Finding{
		Type:     "finding",
		Severity: sev,
		Check:    "secrets",
		File:     relPath,
		Line:     gf.StartLine,
		Message:  gf.Description,
		Snippet:  scan.Redact(line, 100),
	}, true
}

// isEnvVarRef returns true if the value looks like an environment variable
// reference rather than a hardcoded secret.
func isEnvVarRef(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "os.getenv(") {
		return true
	}
	if strings.Contains(lower, "process.env.") {
		return true
	}
	// ${VAR_NAME} patterns — template/env references.
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "${") && strings.HasSuffix(trimmed, "}") {
		return true
	}
	return false
}

// mapSeverity maps a gitleaks finding to a HoneyBadger severity level.
func mapSeverity(gf report.Finding) string {
	desc := strings.ToLower(gf.Description)
	ruleID := strings.ToLower(gf.RuleID)

	// Critical patterns.
	for _, kw := range []string{"private key", "aws", "stripe"} {
		if strings.Contains(desc, kw) || strings.Contains(ruleID, kw) {
			return scan.SevCritical
		}
	}
	return scan.SevHigh
}

// isTestFile returns true if the file path indicates test code.
func isTestFile(path string) bool {
	if strings.HasSuffix(path, "_test.go") {
		return true
	}
	lower := strings.ToLower(path)
	for _, seg := range []string{"testdata/", "test/", "fixtures/", "testdata\\", "test\\", "fixtures\\"} {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

// reduceSeverity lowers severity by one level.
func reduceSeverity(sev string) string {
	switch sev {
	case scan.SevCritical:
		return scan.SevHigh
	case scan.SevHigh:
		return scan.SevMedium
	case scan.SevMedium:
		return scan.SevLow
	case scan.SevLow:
		return scan.SevInfo
	default:
		return sev
	}
}
