package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/famclaw/honeybadger/internal/ignore"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/engine"
)

func TestIgnorePolicyBehavior(t *testing.T) {
	// Table-driven test to validate the ignore policy behavior
	// as per the acceptance criteria
	tests := []struct {
		name               string
		attackerIgnore     string
		trustTarget        bool
		operatorIgnore     string
		findings           []scan.Finding
		expectedVerdict    string
		expectedSuppressed int
		description        string
	}{
		{
			name: "Attacker ignore, trust OFF, no operator",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 0,
			description:        "Should still have findings because target ignore is not trusted",
		},
		{
			name: "Attacker ignore, trust OFF, operator suppresses rule-1",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "SECRET_IN_CODE\n",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 1,
			description:        "Operator suppression works (1 suppressed) but the remaining HIGH finding still fails at family tier; attacker target ignore is not trusted",
		},
		{
			name: "Attacker ignore, trust ON",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    true,
			operatorIgnore: "",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 1,
			description:        "Target ignore is trusted (1 suppressed) but the remaining HIGH finding still fails at family tier",
		},
		{
			name: "Attacker ignore, trust OFF, unrelated operator policy",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "UNRELATED_RULE\n",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 0,
			description:        "Unrelated operator policy should not affect suppression",
		},
		{
			name: "Multiple findings + attacker ignore, trust OFF",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 0,
			description:          "Should have 2 findings when target ignore is not trusted",
		},
		{
			name: "High severity findings, attacker ignore, trust OFF",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 0,
			description:        "Should still FAIL because attacker ignore is not trusted and findings are HIGH severity",
		},
		{
			name: "High severity findings, attacker ignore, trust ON",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    true,
			operatorIgnore: "",
			findings: []scan.Finding{
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
			},
			expectedVerdict:    "FAIL",
			expectedSuppressed: 1,
			description:        "Target ignore is trusted (1 suppressed) but the remaining HIGH finding still fails at family tier",
		},
		{
			name: "Medium severity findings, attacker ignore, trust OFF",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    false,
			operatorIgnore: "",
			findings: []scan.Finding{
				{
					RuleID:   "SECRET_IN_CODE",
					Severity: "MEDIUM",
					File:     "test.go",
					Message:  "Hardcoded secret found",
				},
				{
					RuleID:   "HARDCODED_KEY",
					Severity: "MEDIUM",
					File:     "test.go",
					Message:  "Hardcoded API key found",
				},
			},
			expectedVerdict:    "WARN",
			expectedSuppressed: 0,
			description:        "Should still WARN because attacker ignore is not trusted and findings are MEDIUM severity",
		},
		{
			name: "Medium severity findings, attacker ignore, trust ON",
			attackerIgnore: "SECRET_IN_CODE\n",
			trustTarget:    true,
			operatorIgnore: "",
			findings: []scan.Finding{
				{
					RuleID:   "SECRET_IN_CODE",
					Severity: "MEDIUM",
					File:     "test.go",
					Message:  "Hardcoded secret found",
				},
				{
					RuleID:   "HARDCODED_KEY",
					Severity: "MEDIUM",
					File:     "test.go",
					Message:  "Hardcoded API key found",
				},
			},
			expectedVerdict:    "WARN",
			expectedSuppressed: 1,
			description:        "Should allow suppression when target is trusted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary directory for our test
			tempDir, err := os.MkdirTemp("", "honeybadger-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(tempDir)

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

			// Apply the policy to findings
			outcome := ignore.Apply(pol, tc.findings)

			// Validate outcomes
			if len(outcome.Effective) != len(tc.findings)-tc.expectedSuppressed {
				t.Errorf("Expected %d effective findings, got %d", len(tc.findings)-tc.expectedSuppressed, len(outcome.Effective))
			}

			// Validate applied sources
			if tc.trustTarget && tc.attackerIgnore != "" {
				// Should have applied target
				if len(outcome.Applied) == 0 || !contains(outcome.Applied, "target") {
					t.Errorf("Expected target to be applied, got: %v", outcome.Applied)
				}
			}

			// Validate ignored sources
			if !tc.trustTarget && tc.attackerIgnore != "" {
				// Should have ignored target
				if len(outcome.Ignored) == 0 || !contains(outcome.Ignored, "target") {
					t.Errorf("Expected target to be ignored, got: %v", outcome.Ignored)
				}
			}

			// Validate that the verdict computation is correct
			verdict, _, _ := engine.ComputeVerdict(outcome.Effective, scan.ParanoiaFamily, nil)
			if verdict != tc.expectedVerdict {
				t.Errorf("Expected verdict %s, got %s", tc.expectedVerdict, verdict)
			}
		})
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}