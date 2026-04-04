package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// attestationHTTPClient is a shared HTTP client for attestation API calls.
var attestationHTTPClient = &http.Client{Timeout: 30 * time.Second}

// AttestationAPIBase can be overridden for testing.
var AttestationAPIBase = "https://api.github.com"

// RunAttestation checks build provenance and attestation for a repository.
func RunAttestation(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
	defer close(out)

	// Only run at strict or paranoid paranoia levels.
	if opts.Paranoia != ParanoiaStrict && opts.Paranoia != ParanoiaParanoid {
		return
	}

	// 1. GitHub Attestation API check (if platform is github and not offline)
	if repo.Platform == "github" && !opts.Offline {
		checkGitHubAttestation(ctx, repo, opts, out)
	}

	// 2. Workflow attestation check (if platform is github)
	if repo.Platform == "github" {
		checkAttestationWorkflow(repo, opts, out)
	}

	// 3. SHA256SUMS check
	checkSHA256SUMS(repo, opts, out)

	// 4. Cosign artifacts check
	checkCosignArtifacts(repo, opts, out)
}

func checkGitHubAttestation(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
	if repo.SHA == "" {
		out <- Finding{
			Type:     "finding",
			Severity: SevInfo,
			Check:    "attestation",
			Message:  "No SHA available for attestation verification",
		}
		return
	}

	url := fmt.Sprintf("%s/repos/%s/%s/attestations/sha256:%s",
		AttestationAPIBase, repo.Owner, repo.Name, repo.SHA)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		out <- Finding{
			Type:     "finding",
			Severity: SevInfo,
			Check:    "attestation",
			Message:  fmt.Sprintf("Failed to create attestation API request: %v", err),
		}
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if opts.GithubToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.GithubToken)
	}

	resp, err := attestationHTTPClient.Do(req)
	if err != nil {
		out <- Finding{
			Type:     "finding",
			Severity: SevInfo,
			Check:    "attestation",
			Message:  fmt.Sprintf("Attestation API call failed: %v", err),
		}
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
			out <- Finding{
				Type:     "finding",
				Severity: SevInfo,
				Check:    "attestation",
				Message:  fmt.Sprintf("GitHub attestation verified for SHA %s", repo.SHA),
			}
			return
		}
	}

	// No attestation found
	sev := SevMedium
	if opts.Paranoia == ParanoiaParanoid {
		sev = SevHigh
	}
	out <- Finding{
		Type:     "finding",
		Severity: sev,
		Check:    "attestation",
		Message:  fmt.Sprintf("No GitHub attestation found for SHA %s", repo.SHA),
	}
}

func checkAttestationWorkflow(repo *fetch.Repo, opts Options, out chan<- Finding) {
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
		out <- Finding{
			Type:     "finding",
			Severity: SevInfo,
			Check:    "attestation",
			Message:  "Build attestation workflow configured (actions/attest-build-provenance)",
		}
	} else {
		sev := SevMedium
		if opts.Paranoia == ParanoiaParanoid {
			sev = SevHigh
		}
		out <- Finding{
			Type:     "finding",
			Severity: sev,
			Check:    "attestation",
			Message:  "No build attestation workflow configured",
		}
	}
}

func checkSHA256SUMS(repo *fetch.Repo, opts Options, out chan<- Finding) {
	for path := range repo.Files {
		base := strings.ToLower(path)
		// Check just the filename, not full path
		parts := strings.Split(base, "/")
		filename := parts[len(parts)-1]
		if filename == "sha256sums" || filename == "checksums.txt" {
			out <- Finding{
				Type:     "finding",
				Severity: SevInfo,
				Check:    "attestation",
				File:     path,
				Message:  "SHA256SUMS/checksums file present for release verification",
			}
			return
		}
	}

	if opts.Paranoia == ParanoiaParanoid {
		out <- Finding{
			Type:     "finding",
			Severity: SevHigh,
			Check:    "attestation",
			Message:  "No SHA256SUMS file for release verification",
		}
	}
}

func checkCosignArtifacts(repo *fetch.Repo, opts Options, out chan<- Finding) {
	for path := range repo.Files {
		if strings.HasSuffix(path, ".sig") || strings.HasSuffix(path, ".bundle") || strings.HasSuffix(path, ".sigstore") {
			out <- Finding{
				Type:     "finding",
				Severity: SevInfo,
				Check:    "attestation",
				File:     path,
				Message:  "Cosign signature artifact found",
			}
			return
		}
	}

	if opts.Paranoia == ParanoiaParanoid {
		out <- Finding{
			Type:     "finding",
			Severity: SevMedium,
			Check:    "attestation",
			Message:  "No cosign signature artifacts found",
		}
	}
}
