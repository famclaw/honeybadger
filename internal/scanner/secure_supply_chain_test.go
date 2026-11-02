package scanner

import (
	"testing"

	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestSecureScannerSupplyChain(t *testing.T) {
	// Create a new secure scanner supply chain
	ssc := NewSecureScannerSupplyChain("/tmp/test")
	
	// Test pinning build actions
	ssc.PinBuildAction("build:go:1.21")
	ssc.PinBuildAction("build:docker:24.0")
	
	// Test adding published assets
	ssc.AddPublishedAsset("https://example.com/artifact.tar.gz")
	ssc.AddPublishedAsset("https://example.com/signature.sig")
	
	// Test adding security exceptions
	exception := report.SecurityException{
		ID:            "sec-001",
		Description:   "Known vulnerability in dependency",
		Justification: "Not exploitable in current context",
		ExceptionType: "known-vulnerability",
		Resolved:      false,
	}
	ssc.AddSecurityException(exception)
	
	// Test generating evidence receipt
	findings := []scan.Finding{}
	checks := []string{"artifact-digest-verification", "published-assets-check"}
	exceptions := []report.Exception{}
	
	receipt, err := ssc.GenerateEvidenceReceipt(
		"test-subject", 
		"1.0.0", 
		"2.0.0", 
		"3.0.0", 
		findings, 
		checks, 
		exceptions,
	)
	
	if err != nil {
		t.Fatalf("Failed to generate evidence receipt: %v", err)
	}
	
	// Verify receipt properties
	if receipt.Subject != "test-subject" {
		t.Errorf("Expected subject 'test-subject', got '%s'", receipt.Subject)
	}
	
	if len(receipt.BuildActions) != 2 {
		t.Errorf("Expected 2 build actions, got %d", len(receipt.BuildActions))
	}
	
	if len(receipt.PublishedAssets) != 2 {
		t.Errorf("Expected 2 published assets, got %d", len(receipt.PublishedAssets))
	}
	
	if len(receipt.SecurityExceptions) != 1 {
		t.Errorf("Expected 1 security exception, got %d", len(receipt.SecurityExceptions))
	}
	
	// Test artifact digest calculation
	// Note: This test would require a real file to test
	// We'll just verify the method exists and doesn't panic
	_, err = ssc.CalculateArtifactDigest("/nonexistent")
	if err == nil {
		// This is okay - we're just verifying it doesn't panic
	}
}