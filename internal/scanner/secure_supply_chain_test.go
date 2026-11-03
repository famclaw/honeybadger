package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
)

// writeTestFile writes a runtime fixture into a t.TempDir() directory.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
	return p
}

func TestVerifyArtifactDigest(t *testing.T) {
	dir := t.TempDir()
	ssc := NewSecureScannerSupplyChain(dir)
	p := writeTestFile(t, dir, "artifact.bin", "known artifact content")

	digest, err := ssc.CalculateArtifactDigest(p)
	if err != nil {
		t.Fatalf("CalculateArtifactDigest: %v", err)
	}
	if digest == "" {
		t.Fatal("CalculateArtifactDigest returned an empty digest")
	}

	// Matching baseline must verify.
	ok, err := ssc.VerifyArtifactDigest(p, digest)
	if err != nil {
		t.Fatalf("VerifyArtifactDigest (match): %v", err)
	}
	if !ok {
		t.Error("expected digest verification to succeed for the matching baseline")
	}

	// Wrong baseline must fail.
	ok, err = ssc.VerifyArtifactDigest(p, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("VerifyArtifactDigest (mismatch): %v", err)
	}
	if ok {
		t.Error("expected digest verification to fail for a wrong baseline")
	}

	// Missing file must return an error.
	if _, err := ssc.VerifyArtifactDigest(filepath.Join(dir, "missing.bin"), digest); err == nil {
		t.Error("expected an error verifying a non-existent file")
	}
}

// TestVerifyPublishedAssetsNoBaselineRegression guards against the old stub
// behavior, where any asset whose name contained the substring "valid" was
// marked verified. Assets without a trusted baseline must be "unverified".
func TestVerifyPublishedAssetsNoBaselineRegression(t *testing.T) {
	dir := t.TempDir()
	ssc := NewSecureScannerSupplyChain(dir)
	ssc.AddPublishedAsset("validated-release.tar.gz")
	ssc.AddPublishedAsset("invalid-artifact.bin")
	ssc.AddPublishedAsset("validation-tool.zip")

	results := ssc.VerifyPublishedAssets()
	if len(results) != 3 {
		t.Fatalf("expected 3 asset results, got %d", len(results))
	}
	for _, r := range results {
		if r.Status == AssetVerified {
			t.Errorf("asset %q with no baseline was marked %q; it must never be verified without a baseline", r.Asset, r.Status)
		}
		if r.Status != AssetUnverified {
			t.Errorf("asset %q: expected status %q, got %q", r.Asset, AssetUnverified, r.Status)
		}
	}
}

func TestVerifyPublishedAssetsBaselines(t *testing.T) {
	dir := t.TempDir()
	ssc := NewSecureScannerSupplyChain(dir)

	good := writeTestFile(t, dir, "release.tar.gz", "release content")
	bad := writeTestFile(t, dir, "tool.zip", "tool content")
	goodDigest, err := ssc.CalculateArtifactDigest(good)
	if err != nil {
		t.Fatalf("CalculateArtifactDigest: %v", err)
	}

	// Baseline keyed by basename.
	ssc.AddArtifactBaseline("release.tar.gz", goodDigest)
	// Deliberately wrong baseline.
	ssc.AddArtifactBaseline("tool.zip", strings.Repeat("0", 64))
	// Remote asset with and without a baseline.
	ssc.AddArtifactBaseline("https://example.invalid/artifact.bin", goodDigest)
	ssc.AddPublishedAsset(good)
	ssc.AddPublishedAsset(bad)
	ssc.AddPublishedAsset("https://example.invalid/artifact.bin")
	ssc.AddPublishedAsset("https://example.invalid/no-baseline.bin")

	results := ssc.VerifyPublishedAssets()
	statuses := map[string]string{}
	digests := map[string]string{}
	for _, r := range results {
		statuses[r.Asset] = r.Status
		digests[r.Asset] = r.Digest
	}

	if got := statuses[good]; got != AssetVerified {
		t.Errorf("asset with matching baseline: expected %q, got %q", AssetVerified, got)
	}
	if got := digests[good]; got != goodDigest {
		t.Errorf("verified asset should carry its computed digest")
	}

	if got := statuses[bad]; got != AssetDigestMismatch {
		t.Errorf("asset with wrong baseline: expected %q, got %q", AssetDigestMismatch, got)
	}

	if got := statuses["https://example.invalid/artifact.bin"]; got != AssetUnavailable {
		t.Errorf("remote asset with baseline but no offline fetch: expected %q, got %q", AssetUnavailable, got)
	}

	if got := statuses["https://example.invalid/no-baseline.bin"]; got != AssetUnverified {
		t.Errorf("remote asset without baseline: expected %q, got %q", AssetUnverified, got)
	}
}

func TestCheckBuildActionPin(t *testing.T) {
	cases := []struct {
		action     string
		found      bool
		wantRuleID string
	}{
		// Fully pinned: commit SHA.
		{"actions/checkout@8f4b73f5cef00d4e66f97b0c1e8e9f8b1a2c3d4e", false, ""},
		// Fully pinned: content digest.
		{"ghcr.io/example/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false, ""},
		// Floating reference.
		{"actions/checkout@latest", true, "sup-build-action-floating"},
		{"ghcr.io/example/image:latest", true, "sup-build-action-floating"},
		// Soft reference (tag/branch that can move).
		{"actions/checkout@main", true, "sup-build-action-soft-ref"},
		{"actions/checkout@v4", true, "sup-build-action-soft-ref"},
		// No reference at all.
		{"build-go", true, "sup-build-action-unpinned"},
	}

	for _, tc := range cases {
		finding, found := checkBuildActionPin(tc.action)
		if found != tc.found {
			t.Errorf("checkBuildActionPin(%q): found=%v, want %v", tc.action, found, tc.found)
			continue
		}
		if tc.found && finding.RuleID != tc.wantRuleID {
			t.Errorf("checkBuildActionPin(%q): rule_id=%q, want %q", tc.action, finding.RuleID, tc.wantRuleID)
		}
	}
}

func TestSecureScanRealBehavior(t *testing.T) {
	dir := t.TempDir()
	ssc := NewSecureScannerSupplyChain(dir)

	target := writeTestFile(t, dir, "scan-target.bin", "target content")
	targetDigest, err := ssc.CalculateArtifactDigest(target)
	if err != nil {
		t.Fatalf("CalculateArtifactDigest: %v", err)
	}

	// No baseline registered: digest is calculated, NOT verified, and an
	// INFO finding documents the missing baseline.
	receipt, err := ssc.SecureScan(target, "0.0.0", "0.0.0", "0.0.0")
	if err != nil {
		t.Fatalf("SecureScan (no baseline): %v", err)
	}
	if receipt.Verification != VerificationCalculated {
		t.Errorf("no baseline: expected verification %q, got %q", VerificationCalculated, receipt.Verification)
	}
	if receipt.ArtifactDigest != targetDigest {
		t.Errorf("expected the calculated digest on the receipt")
	}
	if !containsRuleID(receipt, "sup-target-no-baseline") {
		t.Error("no baseline: expected an INFO finding documenting the missing baseline")
	}
	if len(receipt.Checks) != 1 || receipt.Checks[0] != "artifact-digest" {
		t.Errorf("expected only the artifact-digest check to have run, got %v", receipt.Checks)
	}

	// Matching baseline: verification must say "verified".
	ssc.AddArtifactBaseline("scan-target.bin", targetDigest)
	receipt, err = ssc.SecureScan(target, "0.0.0", "0.0.0", "0.0.0")
	if err != nil {
		t.Fatalf("SecureScan (match): %v", err)
	}
	if receipt.Verification != VerificationVerified {
		t.Errorf("matching baseline: expected verification %q, got %q", VerificationVerified, receipt.Verification)
	}
	if len(receipt.Findings) != 0 {
		t.Errorf("matching baseline: expected no findings, got %v", receipt.Findings)
	}

	// Mismatching baseline: verification must say "digest_mismatch" with a
	// HIGH finding.
	ssc.AddArtifactBaseline("scan-target.bin", strings.Repeat("1", 64))
	receipt, err = ssc.SecureScan(target, "0.0.0", "0.0.0", "0.0.0")
	if err != nil {
		t.Fatalf("SecureScan (mismatch): %v", err)
	}
	if receipt.Verification != VerificationDigestMismatch {
		t.Errorf("mismatching baseline: expected verification %q, got %q", VerificationDigestMismatch, receipt.Verification)
	}
	if !containsRuleID(receipt, "sup-target-digest-mismatch") {
		t.Error("mismatching baseline: expected a HIGH digest_mismatch finding")
	}

	// Directory target: no digest check is performed.
	receipt, err = ssc.SecureScan(dir, "0.0.0", "0.0.0", "0.0.0")
	if err != nil {
		t.Fatalf("SecureScan (dir): %v", err)
	}
	if receipt.Verification != VerificationNotPerformed {
		t.Errorf("directory target: expected verification %q, got %q", VerificationNotPerformed, receipt.Verification)
	}
}

func TestSecureScanCollectsFindingsForAssetsAndPins(t *testing.T) {
	dir := t.TempDir()
	ssc := NewSecureScannerSupplyChain(dir)

	asset := writeTestFile(t, dir, "published.bin", "published content")
	assetDigest, err := ssc.CalculateArtifactDigest(asset)
	if err != nil {
		t.Fatalf("CalculateArtifactDigest: %v", err)
	}

	ssc.AddPublishedAsset("published-missing-baseline.bin") // never registered
	ssc.AddPublishedAsset(asset)                            // has a matching baseline
	ssc.AddArtifactBaseline("published.bin", assetDigest)
	ssc.PinBuildAction("actions/checkout@latest") // floating
	ssc.PinBuildAction("build-go")                // no reference
	ssc.AddSecurityException(report.SecurityException{
		ID:          "exc-test",
		Description: "test exception",
	})

	receipt, err := ssc.SecureScan(dir, "0.0.0", "0.0.0", "0.0.0")
	if err != nil {
		t.Fatalf("SecureScan: %v", err)
	}

	if len(receipt.Findings) < 2 {
		t.Fatalf("expected at least 2 real findings, got %d: %v", len(receipt.Findings), receipt.Findings)
	}
	if !containsRuleID(receipt, "sup-asset-no-baseline") {
		t.Error("expected a finding for the published asset without a baseline")
	}
	if !containsRuleID(receipt, "sup-build-action-floating") {
		t.Error("expected a finding for the floating build action reference")
	}
	if !containsRuleID(receipt, "sup-build-action-unpinned") {
		t.Error("expected a finding for the unpinned build action")
	}

	// Checks list must reflect only the checks that actually ran.
	for _, want := range []string{"published-assets", "build-action-pin", "security-exceptions"} {
		if !containsString(receipt.Checks, want) {
			t.Errorf("expected check %q to be recorded, got %v", want, receipt.Checks)
		}
	}
	if containsString(receipt.Checks, "artifact-digest") {
		t.Error("directory target: artifact-digest check must not be recorded")
	}

	// Security exceptions must be documented on the receipt, sorted by ID.
	if len(receipt.SecurityExceptions) != 1 || receipt.SecurityExceptions[0].ID != "exc-test" {
		t.Errorf("expected the registered security exception on the receipt, got %v", receipt.SecurityExceptions)
	}

	// Signed export is not implemented: the field must be gone from the
	// serialized receipt.
	json, err := receipt.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(json), "signed_export") {
		t.Error("receipt JSON must not contain the removed signed_export field")
	}
}

func TestGenerateEvidenceReceipt(t *testing.T) {
	ssc := NewSecureScannerSupplyChain("/tmp")
	ssc.AddSecurityException(report.SecurityException{
		ID:          "exc-a",
		Description: "first exception",
	})
	ssc.AddSecurityException(report.SecurityException{
		ID:          "exc-b",
		Description: "second exception",
	})
	ssc.PinBuildAction("actions/checkout@main")
	ssc.AddPublishedAsset("https://example.invalid/artifact.bin")

	findings := []scan.Finding{}
	receipt, err := ssc.GenerateEvidenceReceipt(
		"test-subject",
		"0.1.0",
		"rules-1",
		"policy-1",
		findings,
		[]string{"check-a", "check-b"},
		[]report.Exception{{ID: "ex-1", Description: "doc exception"}},
	)
	if err != nil {
		t.Fatalf("GenerateEvidenceReceipt: %v", err)
	}

	if receipt.Subject != "test-subject" {
		t.Errorf("subject: got %q", receipt.Subject)
	}
	if receipt.ScannerVersion != "0.1.0" || receipt.RuleVersion != "rules-1" || receipt.PolicyVersion != "policy-1" {
		t.Errorf("version tracking: got %q/%q/%q", receipt.ScannerVersion, receipt.RuleVersion, receipt.PolicyVersion)
	}
	if len(receipt.Checks) != 2 {
		t.Errorf("checks: got %v", receipt.Checks)
	}
	if len(receipt.SecurityExceptions) != 2 ||
		receipt.SecurityExceptions[0].ID != "exc-a" ||
		receipt.SecurityExceptions[1].ID != "exc-b" {
		t.Errorf("security exceptions must be recorded in stable (sorted) order, got %v", receipt.SecurityExceptions)
	}
	if len(receipt.BuildActions) != 1 || receipt.BuildActions[0] != "actions/checkout@main" {
		t.Errorf("build actions: got %v", receipt.BuildActions)
	}
	if len(receipt.PublishedAssets) != 1 {
		t.Errorf("published assets: got %v", receipt.PublishedAssets)
	}

	digest, err := receipt.GenerateDigest()
	if err != nil {
		t.Fatalf("GenerateDigest: %v", err)
	}
	if len(digest) != 64 {
		t.Errorf("expected a hex SHA256 digest, got %q", digest)
	}
}

func containsRuleID(receipt *report.EvidenceReceipt, ruleID string) bool {
	for _, f := range receipt.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
