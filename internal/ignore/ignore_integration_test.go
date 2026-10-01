package ignore

import (
	"os"
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
)

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
