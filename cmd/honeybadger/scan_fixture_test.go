package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/ignore"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestScanFixture(t *testing.T) {
	// Test scanning with various suppression scenarios
	// This mimics the table-driven test from the plan

	// Create a temporary directory for our test
	tempDir, err := os.MkdirTemp("", "honeybadger-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Test cases from the plan
	tests := []struct {
		name           string
		attackerIgnore string
		trustTarget    bool
		operatorIgnore string
		expectFindings int
		malformed      bool
		description    string
	}{
		{
			name:           "Attacker ignore, trust OFF, no operator",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			expectFindings: 2, // Should have 2 findings (the secret and the hard-coded key)
			description:    "Should still have findings because target ignore is not trusted",
		},
		{
			name:           "Attacker ignore, trust OFF, operator suppresses rule-1",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "SECRET_IN_CODE\n",
			expectFindings: 1, // Should have 1 finding (one rule suppressed)
			description:    "Operator suppression should work but attacker ignore is not trusted",
		},
		{
			name:           "Attacker ignore, trust ON",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    true,
			operatorIgnore: "",
			expectFindings: 1, // Only HARDCODED_KEY should remain
			description:    "Should have 1 finding when target ignore is trusted but not all findings suppressed",
		},
		{
			name:           "Attacker ignore, trust OFF, unrelated operator policy",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "UNRELATED_RULE\n",
			expectFindings: 2, // Should have 2 findings (operator policy doesn't suppress)
			description:    "Unrelated operator policy should not affect suppression",
		},
		{
			name:           "Multiple findings + attacker ignore, trust OFF",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			expectFindings: 2, // Both findings should remain (target ignore not trusted)
			description:    "Should have 2 findings when target ignore is not trusted",
		},
		{
			name:           "Env-var row (trust OFF)",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			expectFindings: 2, // Should have 2 findings (the secret and the hard-coded key)
			description:    "Test with trust OFF - should still have 2 findings because attacker ignore is not trusted",
		},
		{
			name:           "Malformed target ignore",
			attackerIgnore: "SECRET_IN_CODE a b\n", // Malformed line with 3 tokens
			trustTarget:    true,
			operatorIgnore: "",
			expectFindings: 2, // Should have 2 findings because malformed target is ignored
			malformed:      true,
			description:    "Malformed target ignore should not cause LoadPolicy to error, Target should be nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock repo structure
			// This would normally be done through the fetcher, but we simulate it here

			// Create the target .honeybadgerignore if it exists
			if tc.attackerIgnore != "" {
				ignoreFile := filepath.Join(tempDir, ".honeybadgerignore")
				if err := os.WriteFile(ignoreFile, []byte(tc.attackerIgnore), 0644); err != nil {
					t.Fatal(err)
				}
			}

			// Create operator policy if it exists
			var operatorFile string
			if tc.operatorIgnore != "" {
				operatorFile = filepath.Join(tempDir, "operator-policy.honeybadgerignore")
				if err := os.WriteFile(operatorFile, []byte(tc.operatorIgnore), 0644); err != nil {
					t.Fatal(err)
				}
			}

			// Test the policy loading
			pol, err := ignore.LoadPolicy(tempDir, operatorFile, tc.trustTarget)
			if err != nil {
				t.Fatalf("Failed to load policy: %v", err)
			}

			// Test the Apply function with sample findings
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

			outcome := ignore.Apply(pol, findings)

			// Validate outcomes
			if len(outcome.Effective) != tc.expectFindings {
				t.Errorf("Expected %d findings, got %d", tc.expectFindings, len(outcome.Effective))
			}

			// Validate applied sources
			// A malformed target leaves Target nil, so nothing is applied even
			// when trusted; a valid target under trust records "target".
			if tc.trustTarget && tc.attackerIgnore != "" {
				if tc.malformed {
					// Target is nil, so nothing should be applied.
					if len(outcome.Applied) > 0 {
						t.Errorf("Expected target to be ignored due to malformed content, got: %v", outcome.Applied)
					}
				} else {
					// For valid targets, should have applied target
					if len(outcome.Applied) == 0 || !strings.Contains(outcome.Applied[0], "target") {
						t.Errorf("Expected target to be applied, got: %v", outcome.Applied)
					}
				}
			}

			// Validate ignored sources
			if !tc.trustTarget && tc.attackerIgnore != "" {
				// Should have ignored target
				if len(outcome.Ignored) == 0 || !strings.Contains(outcome.Ignored[0], "target") {
					t.Errorf("Expected target to be ignored, got: %v", outcome.Ignored)
				}
			}
		})
	}
}
