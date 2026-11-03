package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
)

// SecureScannerSupplyChain implements supply-chain integrity checks for
// scan artifacts and their published assets.
type SecureScannerSupplyChain struct {
	// Base path for artifact verification; relative asset names resolve here.
	BasePath string

	// Build actions that are pinned
	BuildActions []string

	// Published assets to verify
	PublishedAssets []string

	// Security exceptions tracking
	SecurityExceptions map[string]report.SecurityException

	// ArtifactBaselines maps a trusted baseline name to a known-good SHA256
	// digest (lowercase hex, as produced by CalculateArtifactDigest).
	// A baseline may be keyed by full file path, or by basename so that
	// "release.tar.gz" matches "<BasePath>/release.tar.gz".
	ArtifactBaselines map[string]string
}

// NewSecureScannerSupplyChain creates a new secure scanner supply chain
func NewSecureScannerSupplyChain(basePath string) *SecureScannerSupplyChain {
	return &SecureScannerSupplyChain{
		BasePath:           basePath,
		BuildActions:       []string{},
		PublishedAssets:    []string{},
		SecurityExceptions: make(map[string]report.SecurityException),
		ArtifactBaselines:  make(map[string]string),
	}
}

// PinBuildAction pins a build action to the supply chain
func (ssc *SecureScannerSupplyChain) PinBuildAction(action string) {
	ssc.BuildActions = append(ssc.BuildActions, action)
}

// AddPublishedAsset adds a published asset to verify
func (ssc *SecureScannerSupplyChain) AddPublishedAsset(asset string) {
	ssc.PublishedAssets = append(ssc.PublishedAssets, asset)
}

// AddArtifactBaseline registers a known-good SHA256 digest for an asset.
// Baseline names match by full asset string or by basename.
func (ssc *SecureScannerSupplyChain) AddArtifactBaseline(name, expectedDigest string) {
	ssc.ArtifactBaselines[name] = expectedDigest
}

// AddSecurityException adds a security exception to track
func (ssc *SecureScannerSupplyChain) AddSecurityException(exception report.SecurityException) {
	ssc.SecurityExceptions[exception.ID] = exception
}

// Asset verification statuses. "verified" is returned ONLY when the asset's
// computed SHA256 digest was compared against a trusted baseline and matched.
// Every other outcome is explicitly non-verified.
const (
	AssetVerified       = "verified"        // baseline digest matched
	AssetUnverified     = "unverified"      // no trusted baseline (or remote, no baseline)
	AssetDigestMismatch = "digest_mismatch" // baseline present, computed digest differs
	AssetUnavailable    = "unavailable"     // baseline present, asset not readable locally
)

// Artifact digest verification statuses recorded on
// EvidenceReceipt.Verification.
const (
	VerificationNotPerformed   = "not_performed"   // target is not a local readable file
	VerificationCalculated     = "calculated"      // digest computed; no baseline to compare
	VerificationVerified       = "verified"        // digest compared against baseline and matched
	VerificationDigestMismatch = "digest_mismatch" // baseline present, digest differs
	VerificationUnavailable    = "unavailable"     // baseline present, file unreadable
)

// AssetVerification records the verification outcome for one published asset.
type AssetVerification struct {
	Asset  string `json:"asset"`
	Status string `json:"status"`
	// Digest is the computed SHA256 when the asset was readable; empty otherwise.
	Digest string `json:"digest,omitempty"`
	// Note explains the status (e.g. missing baseline, offline remote asset).
	Note string `json:"note,omitempty"`
}

// VerifyPublishedAssets checks each published asset against a trusted
// baseline digest and returns one AssetVerification per asset.
//
// It never claims verification without a baseline: an asset with no
// baseline is "unverified", a baseline mismatch is "digest_mismatch", and an
// asset that cannot be read locally is "unavailable". Remote assets (URLs)
// are not fetched offline; with a baseline they are reported
// "unavailable", without one "unverified".
func (ssc *SecureScannerSupplyChain) VerifyPublishedAssets() []AssetVerification {
	results := make([]AssetVerification, 0, len(ssc.PublishedAssets))
	for _, asset := range ssc.PublishedAssets {
		results = append(results, ssc.verifyAsset(asset))
	}
	return results
}

// verifyAsset checks one published asset against its trusted baseline.
func (ssc *SecureScannerSupplyChain) verifyAsset(asset string) AssetVerification {
	baseline, hasBaseline := ssc.lookupBaseline(asset)
	path := ssc.resolveLocalPath(asset)

	if path == "" {
		if hasBaseline {
			return AssetVerification{
				Asset:  asset,
				Status: AssetUnavailable,
				Note:   "trusted baseline present but asset is not locally readable; offline fetch-and-compare is not implemented",
			}
		}
		return AssetVerification{
			Asset:  asset,
			Status: AssetUnverified,
			Note:   "no trusted baseline digest; assets without a baseline are never marked verified",
		}
	}

	digest, err := ssc.CalculateArtifactDigest(path)
	if err != nil {
		return AssetVerification{
			Asset:  asset,
			Status: AssetUnavailable,
			Note:   fmt.Sprintf("asset could not be read: %v", err),
		}
	}

	if !hasBaseline {
		return AssetVerification{
			Asset:  asset,
			Status: AssetUnverified,
			Digest: digest,
			Note:   "digest calculated but no trusted baseline registered to compare against",
		}
	}

	if !strings.EqualFold(digest, baseline) {
		return AssetVerification{
			Asset:  asset,
			Status: AssetDigestMismatch,
			Digest: digest,
			Note:   "computed digest does not match trusted baseline",
		}
	}

	return AssetVerification{
		Asset:  asset,
		Status: AssetVerified,
		Digest: digest,
	}
}

// lookupBaseline finds the trusted digest for an asset, by full string or
// by basename.
func (ssc *SecureScannerSupplyChain) lookupBaseline(asset string) (string, bool) {
	if d, ok := ssc.ArtifactBaselines[asset]; ok {
		return d, true
	}
	base := filepath.Base(asset)
	if d, ok := ssc.ArtifactBaselines[base]; ok && base != asset {
		return d, true
	}
	return "", false
}

// resolveLocalPath returns a readable local file path for the asset, or ""
// when the asset is not a local file (e.g. a URL) or does not exist.
func (ssc *SecureScannerSupplyChain) resolveLocalPath(asset string) string {
	if strings.Contains(asset, "://") {
		return "" // URL — not fetched offline
	}
	candidate := asset
	if !filepath.IsAbs(candidate) && ssc.BasePath != "" {
		candidate = filepath.Join(ssc.BasePath, candidate)
	}
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() {
		return ""
	}
	return candidate
}

// CalculateArtifactDigest calculates the SHA256 digest of an artifact
func (ssc *SecureScannerSupplyChain) CalculateArtifactDigest(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	digest := hex.EncodeToString(hash.Sum(nil))
	return digest, nil
}

// VerifyArtifactDigest checks if an artifact matches a known digest
func (ssc *SecureScannerSupplyChain) VerifyArtifactDigest(filePath, expectedDigest string) (bool, error) {
	actualDigest, err := ssc.CalculateArtifactDigest(filePath)
	if err != nil {
		return false, err
	}

	return strings.EqualFold(actualDigest, expectedDigest), nil
}

// Build-action pin patterns.
var (
	// fullCommitSHARef matches "owner/name@<40-hex>" commit pins.
	fullCommitSHARef = regexp.MustCompile(`@[0-9a-f]{40}$`)
	// contentDigestRef matches "<image>@sha256:<64-hex>" content-digest pins.
	contentDigestRef = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	// floatingRef matches moving references like "@latest" or ":nightly".
	floatingRef = regexp.MustCompile(`(?i)(@|:)(latest|stable|current|nightly)$`)
)

// checkBuildActionPin inspects one pinned build action reference and returns
// a finding when the reference is not a full pin (commit SHA or content
// digest). Returns (finding, found).
func checkBuildActionPin(action string) (scan.Finding, bool) {
	if floatingRef.MatchString(action) {
		return scan.Finding{
			Type:     "finding",
			Severity: scan.SevMedium,
			Check:    "supplychain",
			RuleID:   "sup-build-action-floating",
			Message:  fmt.Sprintf("build action %q uses a floating reference; pin to a full commit SHA or content digest instead", action),
		}, true
	}
	if fullCommitSHARef.MatchString(action) || contentDigestRef.MatchString(action) {
		return scan.Finding{}, false // fully pinned
	}
	if strings.ContainsAny(action, "@:") {
		return scan.Finding{
			Type:     "finding",
			Severity: scan.SevLow,
			Check:    "supplychain",
			RuleID:   "sup-build-action-soft-ref",
			Message:  fmt.Sprintf("build action %q reference is not a full commit SHA or content digest and may move between builds", action),
		}, true
	}
	return scan.Finding{
		Type:     "finding",
		Severity: scan.SevLow,
		Check:    "supplychain",
		RuleID:   "sup-build-action-unpinned",
		Message:  fmt.Sprintf("build action %q has no version reference; pin to an exact version, commit SHA, or content digest", action),
	}, true
}

// GenerateEvidenceReceipt assembles an evidence receipt from already-collected
// scan data. It performs no checks itself — use SecureScan to run the
// supply-chain checks and populate findings/checks with real results.
func (ssc *SecureScannerSupplyChain) GenerateEvidenceReceipt(
	subject, scannerVersion, ruleVersion, policyVersion string,
	findings []scan.Finding,
	checks []string,
	exceptions []report.Exception,
) (*report.EvidenceReceipt, error) {
	// Create a new evidence receipt
	receipt := report.NewEvidenceReceipt(subject, scannerVersion, ruleVersion, policyVersion)

	// Add findings to the receipt
	for _, finding := range findings {
		receipt.AddFinding(finding)
	}

	// Add checks
	for _, check := range checks {
		receipt.AddCheck(check)
	}

	// Add exceptions
	for _, exception := range exceptions {
		receipt.AddException(exception)
	}

	// Add build actions
	for _, action := range ssc.BuildActions {
		receipt.AddBuildAction(action)
	}

	// Add security exceptions, sorted by ID for a deterministic receipt.
	ids := make([]string, 0, len(ssc.SecurityExceptions))
	for id := range ssc.SecurityExceptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		receipt.AddSecurityException(ssc.SecurityExceptions[id])
	}

	// Add published assets
	for _, asset := range ssc.PublishedAssets {
		receipt.AddPublishedAsset(asset)
	}

	return receipt, nil
}

// SecureScan runs the supply-chain integrity checks and returns an evidence
// receipt that records only what was actually performed.
//
// Checks executed (each appended to receipt.Checks only when it ran):
//
//  1. "artifact-digest" — the SHA256 of target is calculated. If a trusted
//     baseline is registered for target, the digest is compared against it
//     and receipt.Verification is "verified" or "digest_mismatch". Without a
//     baseline it is "calculated" plus an INFO finding — a digest alone is
//     presence, not verification. An unreadable target file is
//     "unavailable" (a LOW finding is emitted only when a baseline exists).
//  2. "published-assets" — each registered asset is verified against its
//     baseline (see VerifyPublishedAssets). Missing baselines and
//     unavailable assets become LOW findings; digest mismatches become
//     HIGH findings.
//  3. "build-action-pin" — each pinned build action is checked for full
//     pinning (commit SHA or content digest). Floating references become
//     MEDIUM findings; soft references become LOW findings.
//  4. "security-exceptions" — recorded when security exceptions are
//     documented on the receipt.
//
// A remote target (URL) or directory has no local file to hash, so the
// artifact-digest check is skipped and receipt.Verification stays
// "not_performed".
func (ssc *SecureScannerSupplyChain) SecureScan(
	target,
	scannerVersion string,
	ruleVersion string,
	policyVersion string,
) (*report.EvidenceReceipt, error) {
	var findings []scan.Finding
	var checks []string

	// targetStatus is the artifact-digest outcome recorded on the receipt.
	targetStatus := VerificationNotPerformed
	// targetDigest is the computed SHA256 when the target was readable.
	targetDigest := ""

	// Check 1: artifact digest of the scan target.
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		checks = append(checks, "artifact-digest")
		baseline, hasBaseline := ssc.lookupBaseline(target)
		digest, calcErr := ssc.CalculateArtifactDigest(target)
		switch {
		case calcErr != nil:
			targetStatus = VerificationUnavailable
			if hasBaseline {
				findings = append(findings, scan.Finding{
					Type:     "finding",
					Severity: scan.SevLow,
					Check:    "supplychain",
					RuleID:   "sup-target-unavailable",
					File:     target,
					Message:  fmt.Sprintf("trusted baseline registered for %q but the artifact could not be read: %v", target, calcErr),
				})
			}
		case !hasBaseline:
			targetStatus = VerificationCalculated
			targetDigest = digest
			findings = append(findings, scan.Finding{
				Type:     "finding",
				Severity: scan.SevInfo,
				Check:    "supplychain",
				RuleID:   "sup-target-no-baseline",
				File:     target,
				Message:  fmt.Sprintf("artifact digest of %q calculated but no trusted baseline registered; digest recorded without verification", target),
			})
		case !strings.EqualFold(digest, baseline):
			targetStatus = VerificationDigestMismatch
			targetDigest = digest
			findings = append(findings, scan.Finding{
				Type:     "finding",
				Severity: scan.SevHigh,
				Check:    "supplychain",
				RuleID:   "sup-target-digest-mismatch",
				File:     target,
				Message:  fmt.Sprintf("artifact digest of %q (%s) does not match trusted baseline %s", target, digest, baseline),
			})
		default:
			targetStatus = VerificationVerified
			targetDigest = digest
		}
	}

	// Check 2: published assets against trusted baselines.
	if len(ssc.PublishedAssets) > 0 {
		checks = append(checks, "published-assets")
		for _, result := range ssc.VerifyPublishedAssets() {
			switch result.Status {
			case AssetUnverified:
				findings = append(findings, scan.Finding{
					Type:     "finding",
					Severity: scan.SevLow,
					Check:    "supplychain",
					RuleID:   "sup-asset-no-baseline",
					File:     result.Asset,
					Message:  fmt.Sprintf("published asset %q could not be verified: %s", result.Asset, result.Note),
				})
			case AssetUnavailable:
				findings = append(findings, scan.Finding{
					Type:     "finding",
					Severity: scan.SevLow,
					Check:    "supplychain",
					RuleID:   "sup-asset-unavailable",
					File:     result.Asset,
					Message:  fmt.Sprintf("published asset %q is not verifiable locally: %s", result.Asset, result.Note),
				})
			case AssetDigestMismatch:
				findings = append(findings, scan.Finding{
					Type:     "finding",
					Severity: scan.SevHigh,
					Check:    "supplychain",
					RuleID:   "sup-asset-digest-mismatch",
					File:     result.Asset,
					Message:  fmt.Sprintf("published asset %q digest %s does not match trusted baseline", result.Asset, result.Digest),
				})
			}
		}
	}

	// Check 3: build action pin strength.
	if len(ssc.BuildActions) > 0 {
		checks = append(checks, "build-action-pin")
		for _, action := range ssc.BuildActions {
			if finding, found := checkBuildActionPin(action); found {
				findings = append(findings, finding)
			}
		}
	}

	// Check 4: security exceptions are gated/documented on the receipt.
	if len(ssc.SecurityExceptions) > 0 {
		checks = append(checks, "security-exceptions")
	}

	// Generate the evidence receipt from the real results.
	receipt, err := ssc.GenerateEvidenceReceipt(
		target,
		scannerVersion,
		ruleVersion,
		policyVersion,
		findings,
		checks,
		[]report.Exception{},
	)
	if err != nil {
		return nil, err
	}

	// Record the artifact-digest outcome on the receipt. "calculated" and
	// "verified" are distinct: only a baseline comparison that matched may
	// say "verified".
	if targetDigest != "" {
		receipt.SetArtifactDigest(targetDigest)
	}
	receipt.SetVerification(targetStatus)

	return receipt, nil
}
