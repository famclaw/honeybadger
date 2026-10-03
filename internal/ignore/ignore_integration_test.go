package ignore

import (
	"os"
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
			expectSuppressed: 1, // Should suppress one finding via operator policy
			expectApplied:    []string{"target", "operator"},
			expectIgnored:    []string{},
			description:      "Both target and operator policies should apply when trust is on",
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
}
