package attestation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

func collectFindings(ch <-chan scan.Finding) []scan.Finding {
	var findings []scan.Finding
	for f := range ch {
		findings = append(findings, f)
	}
	return findings
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRunAttestation(t *testing.T) {
	tests := []struct {
		name         string
		repo         *fetch.Repo
		opts         scan.Options
		wantCount    int // -1 to skip count check
		wantZero     bool
		wantSeverity string
		wantContains string
		mockHandler  http.HandlerFunc // if set, use mock server for API
	}{
		{
			name: "paranoia below strict returns immediately",
			repo: &fetch.Repo{
				Platform: "github",
				Owner:    "test",
				Name:     "repo",
				SHA:      "abc123",
				Files:    map[string][]byte{},
			},
			opts:     scan.Options{Paranoia: scan.ParanoiaFamily},
			wantZero: true,
		},
		{
			name: "github repo with attestation workflow at strict",
			repo: &fetch.Repo{
				Platform: "github",
				Owner:    "test",
				Name:     "repo",
				SHA:      "abc123",
				Files: map[string][]byte{
					".github/workflows/release.yml": []byte(`
name: Release
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest-build-provenance@v1
`),
				},
			},
			opts:         scan.Options{Paranoia: scan.ParanoiaStrict, Offline: true},
			wantCount:    -1,
			wantSeverity: scan.SevInfo,
			wantContains: "Build attestation workflow configured",
		},
		{
			name: "github repo without attestation workflow at strict",
			repo: &fetch.Repo{
				Platform: "github",
				Owner:    "test",
				Name:     "repo",
				SHA:      "abc123",
				Files: map[string][]byte{
					".github/workflows/ci.yml": []byte(`
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`),
				},
			},
			opts:         scan.Options{Paranoia: scan.ParanoiaStrict, Offline: true},
			wantCount:    -1,
			wantSeverity: scan.SevMedium,
			wantContains: "No build attestation workflow configured",
		},
		{
			name: "github repo without attestation workflow at paranoid",
			repo: &fetch.Repo{
				Platform: "github",
				Owner:    "test",
				Name:     "repo",
				SHA:      "abc123",
				Files:    map[string][]byte{},
			},
			opts:         scan.Options{Paranoia: scan.ParanoiaParanoid, Offline: true},
			wantCount:    -1,
			wantSeverity: scan.SevHigh,
			wantContains: "No build attestation workflow configured",
		},
		{
			name: "missing SHA256SUMS on source scan -> INFO",
			repo: &fetch.Repo{
				Platform: "local",
				Owner:    "test",
				Name:     "repo",
				Files:    map[string][]byte{},
			},
			opts:         scan.Options{Paranoia: scan.ParanoiaParanoid, Offline: true},
			wantCount:    -1,
			wantSeverity: scan.SevInfo,
			wantContains: "SHA256SUMS",
		},
		{
			name: "missing SHA256SUMS on release tarball -> HIGH",
			repo: &fetch.Repo{
				Platform: "tarball",
				Owner:    "test",
				Name:     "repo",
				Files:    map[string][]byte{},
			},
			opts:         scan.Options{Paranoia: scan.ParanoiaParanoid, Offline: true},
			wantCount:    -1,
			wantSeverity: scan.SevHigh,
			wantContains: "No SHA256SUMS file for release verification",
		},
		{
			name: "offline mode skips API calls and only checks file presence",
			repo: &fetch.Repo{
				Platform: "github",
				Owner:    "test",
				Name:     "repo",
				SHA:      "abc123",
				Files: map[string][]byte{
					"SHA256SUMS":                    []byte("abc123  binary.tar.gz"),
					"binary.tar.gz.sig":             []byte("signature"),
					".github/workflows/release.yml": []byte("uses: actions/attest-build-provenance@v1"),
				},
			},
			opts:      scan.Options{Paranoia: scan.ParanoiaStrict, Offline: true},
			wantCount: 3, // workflow INFO + SHA256SUMS INFO + cosign INFO
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan scan.Finding, 100)
			errs := make(chan scan.RuntimeError, 4)
			go func() {
				Run(context.Background(), tt.repo, tt.opts, ch, errs)
				close(ch)
				close(errs)
			}()
			findings := collectFindings(ch)

			if tt.wantZero {
				if len(findings) != 0 {
					t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
				}
				return
			}

			if tt.wantCount >= 0 && len(findings) != tt.wantCount {
				t.Errorf("expected %d findings, got %d: %+v", tt.wantCount, len(findings), findings)
			}

			if tt.wantSeverity != "" {
				found := false
				for _, f := range findings {
					if f.Severity == tt.wantSeverity {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected at least one finding with severity %s, got: %+v", tt.wantSeverity, findings)
				}
			}

			if tt.wantContains != "" {
				found := false
				for _, f := range findings {
					if contains(f.Message, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected at least one finding containing %q, got: %+v", tt.wantContains, findings)
				}
			}
		})
	}
}

func TestRunAttestationWithMockAPI(t *testing.T) {
	// The GitHub attestation check is skipped whenever only a commit SHA is
	// available (no sha256: artifact digest), so no attestation API call is made.
	t.Run("commit SHA never used as sha256 subject digest; API skipped", func(t *testing.T) {
		// The mock fails the test if the attestation API is ever called: repo.SHA
		// is a commit SHA, not a sha256: artifact digest, so the check must skip.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("attestation API must not be called with a commit SHA; got %s", r.URL.String())
		}))
		defer server.Close()

		origBase := AttestationAPIBase
		AttestationAPIBase = server.URL
		defer func() { AttestationAPIBase = origBase }()

		repo := &fetch.Repo{
			Platform: "github",
			Owner:    "test",
			Name:     "repo",
			SHA:      "abc123",
			Files: map[string][]byte{
				".github/workflows/release.yml": []byte("uses: actions/attest-build-provenance@v1"),
				"SHA256SUMS":                    []byte("checksum  file"),
				"release.sig":                   []byte("sig"),
			},
		}
		opts := scan.Options{Paranoia: scan.ParanoiaStrict}
		ch := make(chan scan.Finding, 100)
		errs := make(chan scan.RuntimeError, 4)
		go func() {
			Run(context.Background(), repo, opts, ch, errs)
			close(ch)
			close(errs)
		}()
		findings := collectFindings(ch)

		foundSkip := false
		for _, f := range findings {
			if f.RuleID == "att-gh-attestation-skipped" &&
				contains(f.Message, "attestation digest unavailable, skipping cryptographic check") &&
				f.Severity == scan.SevInfo {
				foundSkip = true
			}
		}
		if !foundSkip {
			t.Errorf("expected INFO 'attestation digest unavailable, skipping cryptographic check' (att-gh-attestation-skipped), got: %+v", findings)
		}
		for _, f := range findings {
			if f.RuleID == "att-gh-attestation-present" {
				t.Errorf("did not expect att-gh-attestation-present when the digest is unavailable: %+v", f)
			}
		}
	})

	t.Run("empty SHA short-circuits without API call", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("unexpected API call when SHA is empty")
		}))
		defer server.Close()

		origBase := AttestationAPIBase
		AttestationAPIBase = server.URL
		defer func() { AttestationAPIBase = origBase }()

		repo := &fetch.Repo{
			Platform: "github",
			Owner:    "test",
			Name:     "repo",
			SHA:      "",
			Files:    map[string][]byte{},
		}
		opts := scan.Options{Paranoia: scan.ParanoiaStrict}
		ch := make(chan scan.Finding, 100)
		errs := make(chan scan.RuntimeError, 4)
		go func() {
			Run(context.Background(), repo, opts, ch, errs)
			close(ch)
			close(errs)
		}()
		findings := collectFindings(ch)

		foundEmptySHA := false
		for _, f := range findings {
			if contains(f.Message, "No SHA available for attestation verification") && f.Severity == scan.SevInfo {
				foundEmptySHA = true
			}
		}
		if !foundEmptySHA {
			t.Errorf("expected INFO 'No SHA available for attestation verification' finding, got: %+v", findings)
		}
	})
}
