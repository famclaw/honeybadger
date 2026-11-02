package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/famclaw/honeybadger/internal/scan"
)

// EvidenceReceipt represents a structured receipt of evidence from a scan
type EvidenceReceipt struct {
	// Subject identifies what was scanned
	Subject string `json:"subject"`

	// ScannerVersion indicates the version of the scanner used
	ScannerVersion string `json:"scanner_version"`

	// RuleVersion indicates the version of the ruleset used
	RuleVersion string `json:"rule_version"`

	// PolicyVersion indicates the version of the policy used
	PolicyVersion string `json:"policy_version"`

	// Checks performed during the scan
	Checks []string `json:"checks"`

	// Findings discovered during the scan
	Findings []FindingSummary `json:"findings"`

	// Exceptions documented during the scan
	Exceptions []Exception `json:"exceptions"`

	// ArtifactDigest provides the SHA256 digest of the scanned artifact
	ArtifactDigest string `json:"artifact_digest"`

	// Verification indicates whether artifact digest verification was performed
	Verification string `json:"verification"`

	// PublishedAssets indicates if published assets were verified
	PublishedAssets []string `json:"published_assets,omitempty"`

	// BuildActions indicates pinned build actions
	BuildActions []string `json:"build_actions,omitempty"`

	// SecurityExceptions documents security exceptions
	SecurityExceptions []SecurityException `json:"security_exceptions,omitempty"`

	// Timestamp of when the receipt was generated
	Timestamp time.Time `json:"timestamp"`

	// SignedExport indicates if the receipt is signed
	SignedExport bool `json:"signed_export,omitempty"`
}

// FindingSummary captures essential details about a finding
type FindingSummary struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	MoreInfoURL string `json:"more_info_url,omitempty"`
}

// Exception represents a documented exception in the scan
type Exception struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Justification string `json:"justification"`
	ExemptedBy  string `json:"exempted_by"`
	ExemptedAt  time.Time `json:"exempted_at"`
}

// SecurityException represents a documented security exception
type SecurityException struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Justification string `json:"justification"`
	ExceptionType string `json:"exception_type"`
	Resolved    bool `json:"resolved,omitempty"`
	ResolvedAt  time.Time `json:"resolved_at,omitempty"`
}

// NewEvidenceReceipt creates a new evidence receipt
func NewEvidenceReceipt(subject, scannerVersion, ruleVersion, policyVersion string) *EvidenceReceipt {
	return &EvidenceReceipt{
		Subject:         subject,
		ScannerVersion:  scannerVersion,
		RuleVersion:     ruleVersion,
		PolicyVersion:   policyVersion,
		Checks:          []string{},
		Findings:        []FindingSummary{},
		Exceptions:      []Exception{},
		ArtifactDigest:  "",
		Verification:    "not_performed",
		PublishedAssets: []string{},
		BuildActions:    []string{},
		SecurityExceptions: []SecurityException{},
		Timestamp:       time.Now(),
		SignedExport:    false,
	}
}

// AddFinding adds a finding to the evidence receipt
func (er *EvidenceReceipt) AddFinding(finding scan.Finding) {
	fs := FindingSummary{
		ID:          finding.ID,
		RuleID:      finding.RuleID,
		Severity:    finding.Severity,
		Message:     finding.Message,
		File:        finding.File,
		Line:        finding.Line,
		MoreInfoURL: finding.MoreInfoURL,
	}
	er.Findings = append(er.Findings, fs)
}

// AddCheck adds a check to the evidence receipt
func (er *EvidenceReceipt) AddCheck(check string) {
	er.Checks = append(er.Checks, check)
}

// AddException adds an exception to the evidence receipt
func (er *EvidenceReceipt) AddException(exception Exception) {
	er.Exceptions = append(er.Exceptions, exception)
}

// AddPublishedAsset adds a published asset to the evidence receipt
func (er *EvidenceReceipt) AddPublishedAsset(asset string) {
	er.PublishedAssets = append(er.PublishedAssets, asset)
}

// AddBuildAction adds a build action to the evidence receipt
func (er *EvidenceReceipt) AddBuildAction(action string) {
	er.BuildActions = append(er.BuildActions, action)
}

// AddSecurityException adds a security exception to the evidence receipt
func (er *EvidenceReceipt) AddSecurityException(exception SecurityException) {
	er.SecurityExceptions = append(er.SecurityExceptions, exception)
}

// SetArtifactDigest sets the artifact digest
func (er *EvidenceReceipt) SetArtifactDigest(digest string) {
	er.ArtifactDigest = digest
}

// SetVerification sets the verification status
func (er *EvidenceReceipt) SetVerification(status string) {
	er.Verification = status
}

// SetSignedExport marks the receipt as signed
func (er *EvidenceReceipt) SetSignedExport(signed bool) {
	er.SignedExport = signed
}

// GenerateDigest calculates and returns the SHA256 digest of the receipt
func (er *EvidenceReceipt) GenerateDigest() (string, error) {
	data, err := json.Marshal(er)
	if err != nil {
		return "", err
	}
	
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// MarshalJSON custom marshaling for EvidenceReceipt to avoid circular references
func (er *EvidenceReceipt) MarshalJSON() ([]byte, error) {
	// Create a copy to avoid infinite recursion
	type Alias EvidenceReceipt
	return json.Marshal(&struct {
		Timestamp string `json:"timestamp"`
		*Alias
	}{
		Timestamp: er.Timestamp.Format(time.RFC3339),
		Alias:     (*Alias)(er),
	})
}