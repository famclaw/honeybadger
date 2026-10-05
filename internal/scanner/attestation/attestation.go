package attestation

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// AttestationAPIBase documents the GitHub attestation endpoint base and can be
// overridden for testing. It is not dereferenced when the check is skipped
// because no proper subject digest is available (see checkGitHubAttestation).
var AttestationAPIBase = "https://api.github.com"

// Run checks build provenance and attestation for a repository.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding, errs chan<- scan.RuntimeError) {
	// Only run at strict or paranoid paranoia levels.
	if opts.Paranoia != scan.ParanoiaStrict && opts.Paranoia != scan.ParanoiaParanoid {
		return
	}

	// 1. GitHub Attestation API check (if platform is github and not offline)
	if repo.Platform == "github" && !opts.Offline {
		checkGitHubAttestation(ctx, repo, opts, out, errs)
	}

	// 2. Workflow attestation check (if platform is github)
	if repo.Platform == "github" {
		checkAttestationWorkflow(repo, opts, out)
	}

	// 3. Check for committed binaries in bin/ directory
	checkCommittedBinaries(repo, opts, out)

	// 4. SHA256SUMS check
	checkSHA256SUMS(repo, opts, out)

	// 5. Cosign artifacts check
	checkCosignArtifacts(repo, opts, out)
}

func checkGitHubAttestation(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding, errs chan<- scan.RuntimeError) {
	if repo.SHA == "" {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevInfo,
			Check:    "attestation",
			Message:  "No SHA available for attestation verification",
		}
		return
	}

	// repo.SHA is a git commit SHA, not a SHA-256 artifact digest. The GitHub
	// attestation endpoint is keyed by a subject digest
	// (sha256:<artifact-digest>), and no release-asset digest is available in this
	// code path. Querying with sha256:<commit-SHA> could never match a real
	// attestation bundle, so skip the cryptographic attestation check rather than
	// emit a false negative.
	out <- scan.Finding{
		Type:     "finding",
		Severity: scan.SevInfo,
		Check:    "attestation",
		RuleID:   "att-gh-attestation-skipped",
		Message:  "attestation digest unavailable, skipping cryptographic check",
	}
}

func checkAttestationWorkflow(repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	found := false
	for path, content := range repo.Files {
		if strings.HasPrefix(path, ".github/workflows/") && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			if strings.Contains(string(content), "actions/attest-build-provenance") {
				found = true
				break
			}
		}
	}

	if found {
		// RuleID att-gh-workflow-configured is the source-level signal that
		// build-attestation infrastructure is present; it drives the result
		// event's Attested flag (see attestationPresent). The cryptographic
		// attestation API check is unavailable for source scans, so a
		// configured attestation workflow is the strongest "attested" evidence
		// we can emit from a source tree.
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevInfo,
			Check:    "attestation",
			RuleID:   "att-gh-workflow-configured",
			Message:  "Build attestation workflow configured (actions/attest-build-provenance)",
		}
	} else {
		sev := scan.SevMedium
		if opts.Paranoia == scan.ParanoiaParanoid {
			sev = scan.SevHigh
		}
		out <- scan.Finding{
			Type:     "finding",
			Severity: sev,
			Check:    "attestation",
			Message:  "No build attestation workflow configured",
		}
	}
}

// isReleaseArtifactScan reports whether the scan target is a packaged release
// artifact rather than a source tree. SHA256SUMS and cosign signatures are
// produced at release time and published as release assets — they never live
// in a source repository — so their absence is only a finding when a release
// artifact is being scanned.
func isReleaseArtifactScan(repo *fetch.Repo) bool {
	return repo.Platform == "tarball"
}

// isExecutableBinary checks if the content appears to be an executable binary
// by checking for common executable file signatures (magic bytes) or shebang.
// It uses the shared scan.IsExecutable function.
func isExecutableBinary(data []byte) bool {
	return scan.IsExecutable(data)
}

func checkSHA256SUMS(repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	for path := range repo.Files {
		base := strings.ToLower(path)
		// Check just the filename, not full path
		parts := strings.Split(base, "/")
		filename := parts[len(parts)-1]
		if filename == "sha256sums" || filename == "checksums.txt" {
			out <- scan.Finding{
				Type:     "finding",
				Severity: scan.SevInfo,
				Check:    "attestation",
				File:     path,
				Message:  "SHA256SUMS/checksums file present for release verification",
			}
			return
		}
	}

	if opts.Paranoia != scan.ParanoiaParanoid {
		return
	}
	if isReleaseArtifactScan(repo) {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevHigh,
			Check:    "attestation",
			Message:  "No SHA256SUMS file for release verification",
		}
		return
	}
	// Source-tree scan: release artifacts legitimately do not exist yet. This
	// stays INFO so it never blocks — ComputeVerdict's rule that INFO never
	// escalates the verdict is what keeps a source self-scan green at paranoid.
	out <- scan.Finding{
		Type:     "finding",
		Severity: scan.SevInfo,
		Check:    "attestation",
		Message:  "No SHA256SUMS file in scanned source; release-artifact verification requires scanning a published release",
	}
}

func checkCosignArtifacts(repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	for path := range repo.Files {
		if strings.HasSuffix(path, ".sig") || strings.HasSuffix(path, ".bundle") || strings.HasSuffix(path, ".sigstore") {
			out <- scan.Finding{
				Type:     "finding",
				Severity: scan.SevInfo,
				Check:    "attestation",
				File:     path,
				Message:  "Cosign signature artifact found",
			}
			return
		}
	}

	if opts.Paranoia != scan.ParanoiaParanoid {
		return
	}
	if isReleaseArtifactScan(repo) {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevMedium,
			Check:    "attestation",
			Message:  "No cosign signature artifacts found",
		}
		return
	}
	out <- scan.Finding{
		Type:     "finding",
		Severity: scan.SevInfo,
		Check:    "attestation",
		Message:  "No cosign signature artifacts in scanned source; signature verification requires scanning a published release",
	}
}

// checkCommittedBinaries checks for committed binaries in the bin/ directory and flags them
// as lacking build provenance at strict/paranoid levels
func checkCommittedBinaries(repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	for path, content := range repo.Files {
		if strings.HasPrefix(path, "bin/") && isExecutableBinary(content) {
			// Skip common pre-built binary extensions that are typically legitimate
			// and don't need provenance checks (e.g., .so for shared libraries)
			ext := filepath.Ext(path)
			if ext == ".so" || ext == ".dylib" || ext == ".dll" {
				continue
			}

			sev := scan.SevMedium
			if opts.Paranoia == scan.ParanoiaParanoid {
				sev = scan.SevHigh
			}
			out <- scan.Finding{
				Type:     "finding",
				Severity: sev,
				Check:    "attestation",
				RuleID:   "att-bin-no-provenance",
				Message:  fmt.Sprintf("Binary %s has no build provenance (no SHA256SUMS/cosign)", path),
			}
		}
	}
}
