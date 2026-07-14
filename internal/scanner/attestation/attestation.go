package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// attestationHTTPClient is a shared HTTP client for attestation API calls.
var attestationHTTPClient = &http.Client{Timeout: 30 * time.Second}

// AttestationAPIBase can be overridden for testing.
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

	url := fmt.Sprintf("%s/repos/%s/%s/attestations/sha256:%s",
		AttestationAPIBase, repo.Owner, repo.Name, repo.SHA)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		errs <- scan.NewRuntimeError("attestation", fmt.Sprintf("create request for %s/%s sha=%s: %v", repo.Owner, repo.Name, repo.SHA, err))
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if opts.GithubToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.GithubToken)
	}

	resp, err := attestationHTTPClient.Do(req)
	if err != nil {
		errs <- scan.NewRuntimeError("attestation", fmt.Sprintf("API call %s/%s sha=%s: %v", repo.Owner, repo.Name, repo.SHA, err))
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		// Check if there are actual attestations in the response
		var result struct {
			Attestations []json.RawMessage `json:"attestations"`
		}
		if err := json.Unmarshal(body, &result); err == nil && len(result.Attestations) > 0 {
			out <- scan.Finding{
				Type:     "finding",
				Severity: scan.SevInfo,
				Check:    "attestation",
				Message:  fmt.Sprintf("GitHub attestation verified for SHA %s", repo.SHA),
			}
			return
		}
	}

	// No attestation found
	sev := scan.SevMedium
	if opts.Paranoia == scan.ParanoiaParanoid {
		sev = scan.SevHigh
	}
	out <- scan.Finding{
		Type:     "finding",
		Severity: sev,
		Check:    "attestation",
		Message:  fmt.Sprintf("No GitHub attestation found for SHA %s", repo.SHA),
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
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevInfo,
			Check:    "attestation",
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
// by checking for common executable file signatures (magic bytes)
func isExecutableBinary(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	// Check for ELF magic bytes: 0x7f 'E' 'L' 'F'
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}
	
	// Check for Mach-O magic bytes
	// MH_MAGIC: 0xFEEDFACE, MH_CIGAM: 0xCEFAEDFE (big/little endian)
	if len(data) >= 4 {
		if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && data[3] == 0xCE) ||
			(data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE) {
			return true
		}
		// MH_MAGIC_64: 0xFEEDFACF, MH_CIGAM_64: 0xCFFFAEDF
		if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && data[3] == 0xCF) ||
			(data[0] == 0xCF && data[1] == 0xFF && data[2] == 0xFF && data[3] == 0xED) {
			return true
		}
	}
	
	// Check for PE (Windows executable) magic bytes: 'M' 'Z'
	if data[0] == 'M' && data[1] == 'Z' {
		return true
	}
	
	return false
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
