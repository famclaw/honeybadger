package main

import (
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
)

func TestAttestationPresent(t *testing.T) {
	tests := []struct {
		name     string
		findings []scan.Finding
		want     bool
	}{
		{
			name: "workflow configured finding sets attested",
			findings: []scan.Finding{
				{
					Type:     "finding",
					Severity: scan.SevInfo,
					Check:    "attestation",
					RuleID:   "att-gh-workflow-configured",
					Message:  "Build attestation workflow configured (actions/attest-build-provenance)",
				},
			},
			want: true,
		},
		{
			name: "skipped finding does not set attested",
			findings: []scan.Finding{
				{
					Type:     "finding",
					Severity: scan.SevInfo,
					Check:    "attestation",
					RuleID:   "att-gh-attestation-skipped",
					Message:  "attestation digest unavailable, skipping cryptographic check",
				},
			},
			want: false,
		},
		{
			name:     "empty findings returns false",
			findings: []scan.Finding{},
			want:     false,
		},
		{
			name: "non-attestation check with same RuleID does not set attested",
			findings: []scan.Finding{
				{
					Type:     "finding",
					Severity: scan.SevInfo,
					Check:    "supplychain",
					RuleID:   "att-gh-workflow-configured",
					Message:  "irrelevant",
				},
			},
			want: false,
		},
		{
			name: "mixed findings with workflow configured",
			findings: []scan.Finding{
				{
					Type:     "finding",
					Severity: scan.SevInfo,
					Check:    "attestation",
					RuleID:   "att-gh-attestation-skipped",
					Message:  "attestation digest unavailable, skipping cryptographic check",
				},
				{
					Type:     "finding",
					Severity: scan.SevInfo,
					Check:    "attestation",
					RuleID:   "att-gh-workflow-configured",
					Message:  "Build attestation workflow configured (actions/attest-build-provenance)",
				},
				{
					Type:     "finding",
					Severity: scan.SevHigh,
					Check:    "secrets",
					RuleID:   "sec-aws-key",
					Message:  "AWS key found",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attestationPresent(tt.findings)
			if got != tt.want {
				t.Errorf("attestationPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}
