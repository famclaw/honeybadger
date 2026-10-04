package ignore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
)

// TestMalformedTargetIgnoreDoesNotAbort reproduces the DoS regression: an
// attacker-controlled target .honeybadgerignore with a malformed line
// (more than two tokens) must not abort the scan. LoadPolicyFromContent must
// return a policy with Target==nil so the scan continues without target
// suppressions, while operator policy behavior is preserved.
func TestMalformedTargetIgnoreDoesNotAbort(t *testing.T) {
	findings := []scan.Finding{
		{RuleID: "SECRET_IN_CODE", Severity: scan.SevHigh, File: "main.go", Message: "hardcoded secret"},
		{RuleID: "HARDCODED_KEY", Severity: scan.SevHigh, File: "main.go", Message: "hardcoded key"},
	}

	// Malformed target content: one line with three tokens.
	malformed := "MY_RULE a b\nSECRET_IN_CODE\n"

	// No operator policy: the malformed target must not error, and Target must
	// be nil so no findings are suppressed.
	policy, err := LoadPolicyFromContent([]byte(malformed), "", false)
	if err != nil {
		t.Fatalf("LoadPolicyFromContent must not error on malformed target content: %v", err)
	}
	if policy.Target != nil {
		t.Fatalf("expected Target to be nil after malformed parse, got %v", policy.Target)
	}
	out := Apply(policy, findings)
	if len(out.Effective) != len(findings) {
		t.Fatalf("expected no suppression (Target nil), got %d effective of %d", len(out.Effective), len(findings))
	}

	// With a trusted operator policy, the malformed target is dropped but the
	// operator policy must still suppress matching findings.
	tmp, err := os.CreateTemp("", "operator-policy-*")
	if err != nil {
		t.Fatalf("create operator policy: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("HARDCODED_KEY\n"); err != nil {
		t.Fatalf("write operator policy: %v", err)
	}
	tmp.Close()

	policy, err = LoadPolicyFromContent([]byte(malformed), tmp.Name(), false)
	if err != nil {
		t.Fatalf("LoadPolicyFromContent with operator policy must not error: %v", err)
	}
	if policy.Target != nil {
		t.Fatalf("expected Target nil, got %v", policy.Target)
	}
	if policy.Operator == nil {
		t.Fatalf("expected operator policy to load")
	}
	out = Apply(policy, findings)
	if len(out.Suppressed) != 1 {
		t.Fatalf("expected operator to suppress 1 finding, got %d", len(out.Suppressed))
	}
	if len(out.Effective) != 1 {
		t.Fatalf("expected 1 effective finding, got %d", len(out.Effective))
	}
	if len(out.Applied) != 1 || out.Applied[0] != "operator" {
		t.Fatalf("expected applied=[operator], got %v", out.Applied)
	}
}

// TestIntegrationTargetIgnoreControl tests the key scenario from the security audit
func TestIntegrationTargetIgnoreControl(t *testing.T) {
	// Test cases for attacker-controlled target ignore behavior
	tests := []struct {
		name             string
		targetIgnore     string
		trustTarget      bool
		operatorIgnore   string
		expectSuppressed int
		expectApplied    []string
		expectIgnored    []string
		description      string
	}{
		{
			name:             "Attacker ignore, trust OFF",
			targetIgnore:     "SECRET_IN_CODE\n",
			trustTarget:      false,
			operatorIgnore:   "",
			expectSuppressed: 0, // Should not suppress anything
			expectApplied:    []string{},
			expectIgnored:    []string{"target"},
			description:      "Target ignore should be ignored when trust is off",
		},
		{
			name:             "Attacker ignore, trust ON",
			targetIgnore:     "SECRET_IN_CODE\n",
			trustTarget:      true,
			operatorIgnore:   "",
			expectSuppressed: 1, // Should suppress one finding
			expectApplied:    []string{"target"},
			expectIgnored:    []string{},
			description:      "Target ignore should be applied when trust is on",
		},
		{
			name:             "Attacker ignore, trust OFF, operator suppresses",
			targetIgnore:     "SECRET_IN_CODE\n",
			trustTarget:      false,
			operatorIgnore:   "SECRET_IN_CODE\n",
			expectSuppressed: 1, // Should suppress one finding via operator policy
			expectApplied:    []string{"operator"},
			expectIgnored:    []string{"target"},
			description:      "Operator policy should work regardless of target trust",
		},
		{
			name:             "Attacker ignore, trust ON, operator suppresses",
			targetIgnore:     "SECRET_IN_CODE\n",
			trustTarget:      true,
			operatorIgnore:   "SECRET_IN_CODE\n",
			expectSuppressed: 1, // Should suppress one finding via target policy (operator suppresses none due to prior suppression)
			expectApplied:    []string{"target"},
			expectIgnored:    []string{},
			description:      "Target policy should apply first, then operator policy suppresses nothing (due to prior suppression)",
		},
		{
			name:             "No target ignore, operator suppresses",
			targetIgnore:     "",
			trustTarget:      false,
			operatorIgnore:   "SECRET_IN_CODE\n",
			expectSuppressed: 1, // Should suppress one finding
			expectApplied:    []string{"operator"},
			expectIgnored:    []string{},
			description:      "Operator policy should work when no target ignore exists",
		},
		{
			name:             "Malformed target ignore, trust OFF",
			targetIgnore:     "SECRET_IN_CODE a b\n", // Malformed line with 3 tokens
			trustTarget:      false,
			operatorIgnore:   "",
			expectSuppressed: 0, // Should not suppress anything due to malformed target
			expectApplied:    []string{},
			expectIgnored:    []string{}, // Target is nil, so no ignored sources
			description:      "Malformed target ignore should not cause LoadPolicy to error, Target should be nil",
		},
		{
			name:             "Malformed target ignore, trust ON",
			targetIgnore:     "SECRET_IN_CODE a b\n", // Malformed line with 3 tokens
			trustTarget:      true,
			operatorIgnore:   "",
			expectSuppressed: 0, // Should not suppress anything due to malformed target
			expectApplied:    []string{},
			expectIgnored:    []string{}, // Target is nil, so no ignored sources
			description:      "Malformed target ignore should not cause LoadPolicy to error, Target should be nil",
		},
		{
			name:             "Trusted target present but zero matching findings",
			targetIgnore:     "UNRELATED_RULE\n",
			trustTarget:      true,
			operatorIgnore:   "",
			expectSuppressed: 0,
			expectApplied:    []string{"target"},
			expectIgnored:    []string{},
			description:      "Auditability: trusted target with no matches must still record 'target' in Applied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock policy with the test conditions
			var targetContent []byte
			if tc.targetIgnore != "" {
				targetContent = []byte(tc.targetIgnore)
			}

			// Create operator policy file if needed
			var operatorPolicyFile string
			if tc.operatorIgnore != "" {
				// Create a temporary file for the operator policy
				tmpFile, err := os.CreateTemp("", "operator-policy-*")
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(tc.operatorIgnore)
				if err != nil {
					t.Fatalf("Failed to write to temp file: %v", err)
				}
				tmpFile.Close()
				operatorPolicyFile = tmpFile.Name()
			}

			// Load policy with content from repo files
			policy, err := LoadPolicyFromContent(targetContent, operatorPolicyFile, tc.trustTarget)
			if err != nil {
				t.Fatalf("Failed to load policy: %v", err)
			}

			// Create test findings that would be suppressed
			findings := []scan.Finding{
				{
					RuleID:   "SECRET_IN_CODE",
					Severity: "HIGH",
					File:     "test.go",
					Message:  "Hardcoded secret found",
				},
				{
					RuleID:   "HARDCODED_KEY",
					Severity: "HIGH",
					File:     "test.go",
					Message:  "Hardcoded API key found",
				},
			}

			// Apply the policy
			outcome := Apply(policy, findings)

			// Validate suppression count
			if len(outcome.Suppressed) != tc.expectSuppressed {
				t.Errorf("Expected %d suppressed findings, got %d", tc.expectSuppressed, len(outcome.Suppressed))
			}

			// Validate applied sources
			if len(outcome.Applied) != len(tc.expectApplied) {
				t.Errorf("Expected applied sources %v, got %v", tc.expectApplied, outcome.Applied)
			}

			// Validate ignored sources
			if len(outcome.Ignored) != len(tc.expectIgnored) {
				t.Errorf("Expected ignored sources %v, got %v", tc.expectIgnored, outcome.Ignored)
			}
		})
	}

	// Exercise the filesystem-backed LoadPolicy path with runtime fixtures.
	t.Run("LoadPolicy_MalformedTarget", func(t *testing.T) {
		targetDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(targetDir, ".honeybadgerignore"),
			[]byte("MY_RULE a b\nSECRET_IN_CODE\n"), 0o644); err != nil {
			t.Fatalf("write target ignore: %v", err)
		}

		// Malformed target .honeybadgerignore must not error and must leave
		// Target nil regardless of trust flag.
		for _, trust := range []bool{false, true} {
			policy, err := LoadPolicy(targetDir, "", trust)
			if err != nil {
				t.Fatalf("LoadPolicy must not error on malformed target (trust=%v): %v", trust, err)
			}
			if policy.Target != nil {
				t.Fatalf("expected Target nil after malformed parse (trust=%v), got %v", trust, policy.Target)
			}
		}

		// Malformed operator policy is fatal.
		malformedOp := filepath.Join(targetDir, "operator-malformed.policy")
		if err := os.WriteFile(malformedOp, []byte("MALFORMED_LINE a b c\n"), 0o644); err != nil {
			t.Fatalf("write operator policy: %v", err)
		}
		if _, err := LoadPolicy(targetDir, malformedOp, false); err == nil {
			t.Fatal("LoadPolicy should error on malformed operator policy")
		}

		// Missing operator policy file is fatal.
		missingOp := filepath.Join(targetDir, "does-not-exist.policy")
		if _, err := LoadPolicy(targetDir, missingOp, false); err == nil {
			t.Fatal("LoadPolicy should error on missing operator policy file")
		}
	})
}

// TestApplyTrustedTargetNoMatchesStillApplied is a regression test for the
// auditability gap: a trusted target .honeybadgerignore that is present and
// parses successfully but matches zero findings must still record "target" in
// Outcome.Applied. Before the fix it appeared in neither Applied nor Ignored,
// so main.go's emission guard (len(Applied)>0 || len(Ignored)>0) dropped the
// suppression event entirely, making it impossible for an auditor to tell
// "no target ignore file" from "target ignore file present, trusted, but no
// matches."
func TestApplyTrustedTargetNoMatchesStillApplied(t *testing.T) {
	findings := []scan.Finding{
		{RuleID: "SECRET_IN_CODE", Severity: scan.SevHigh, File: "main.go", Message: "hardcoded secret"},
		{RuleID: "HARDCODED_KEY", Severity: scan.SevHigh, File: "main.go", Message: "hardcoded key"},
	}

	// A trusted target policy that matches none of the findings above.
	targetSet, err := Parse([]byte("UNRELATED_RULE\n"), ".honeybadgerignore")
	if err != nil {
		t.Fatalf("parse target policy: %v", err)
	}

	// Case 1: trusted target present but no matches.
	withTarget := Apply(&Policy{TrustTarget: true, Target: targetSet}, findings)
	if len(withTarget.Effective) != len(findings) {
		t.Fatalf("expected %d effective findings (none suppressed), got %d", len(findings), len(withTarget.Effective))
	}
	if len(withTarget.Suppressed) != 0 {
		t.Fatalf("expected 0 suppressed, got %d", len(withTarget.Suppressed))
	}
	if len(withTarget.Applied) != 1 || withTarget.Applied[0] != "target" {
		t.Fatalf("expected Applied=[target] for trusted no-match target, got %v", withTarget.Applied)
	}
	if len(withTarget.Ignored) != 0 {
		t.Fatalf("expected Ignored empty, got %v", withTarget.Ignored)
	}

	// Case 2: no target policy at all. This must remain indistinguishable in
	// Effective/Suppressed but DIFFERENT in Applied, so an auditor can tell the
	// two situations apart.
	noTarget := Apply(&Policy{TrustTarget: true}, findings)
	if len(noTarget.Applied) != 0 {
		t.Fatalf("expected Applied empty when no target policy present, got %v", noTarget.Applied)
	}
	if len(noTarget.Ignored) != 0 {
		t.Fatalf("expected Ignored empty when no target policy present, got %v", noTarget.Ignored)
	}
	if len(noTarget.Effective) != len(findings) {
		t.Fatalf("expected %d effective findings, got %d", len(findings), len(noTarget.Effective))
	}

	// The two cases must now be distinguishable via Applied.
	if hasString(withTarget.Applied, "target") == hasString(noTarget.Applied, "target") {
		t.Fatalf("trusted no-match target and no-target policy must differ in Applied: with=%v without=%v", withTarget.Applied, noTarget.Applied)
	}
}

// TestApplyUntrustedTargetNoMatchesStillIgnored confirms the mirror case: an
// untrusted target policy that matches nothing still records "target" in
// Ignored (this behavior was already unconditional and is preserved).
func TestApplyUntrustedTargetNoMatchesStillIgnored(t *testing.T) {
	findings := []scan.Finding{
		{RuleID: "SECRET_IN_CODE", Severity: scan.SevHigh, File: "main.go", Message: "hardcoded secret"},
	}
	targetSet, err := Parse([]byte("UNRELATED_RULE\n"), ".honeybadgerignore")
	if err != nil {
		t.Fatalf("parse target policy: %v", err)
	}

	out := Apply(&Policy{TrustTarget: false, Target: targetSet}, findings)
	if len(out.Applied) != 0 {
		t.Fatalf("expected Applied empty for untrusted target, got %v", out.Applied)
	}
	if len(out.Ignored) != 1 || out.Ignored[0] != "target" {
		t.Fatalf("expected Ignored=[target] for untrusted target, got %v", out.Ignored)
	}
	if len(out.Effective) != len(findings) {
		t.Fatalf("expected %d effective findings, got %d", len(findings), len(out.Effective))
	}
}

func hasString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
