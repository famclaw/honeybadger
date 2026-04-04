package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
)

func TestRunAttestation(t *testing.T) {
	tests := []struct {
		name         string
		repo         *fetch.Repo
		opts         Options
		wantCount    int    // -1 to skip count check
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
			opts:     Options{Paranoia: ParanoiaFamily},
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
			opts: Options{Paranoia: ParanoiaStrict, Offline: true},
			wantCount:    -1,
			wantSeverity: SevInfo,
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
			opts:         Options{Paranoia: ParanoiaStrict, Offline: true},
			wantCount:    -1,
			wantSeverity: SevMedium,
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
			opts:         Options{Paranoia: ParanoiaParanoid, Offline: true},
			wantCount:    -1,
			wantSeverity: SevHigh,
			wantContains: "No build attestation workflow configured",
		},
		{
			name: "missing SHA256SUMS at paranoid",
			repo: &fetch.Repo{
				Platform: "local",
				Owner:    "test",
				Name:     "repo",
				Files:    map[string][]byte{},
			},
			opts:         Options{Paranoia: ParanoiaParanoid, Offline: true},
			wantCount:    -1,
			wantSeverity: SevHigh,
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
			opts:  Options{Paranoia: ParanoiaStrict, Offline: true},
			wantCount: 3, // workflow INFO + SHA256SUMS INFO + cosign INFO
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan Finding, 100)
			go RunAttestation(context.Background(), tt.repo, tt.opts, ch)
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
	// Test with mock HTTP server for GitHub attestation API
	t.Run("API returns attestation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"attestations": []map[string]interface{}{
					{"bundle": "test"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		// Override the API base for this test
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
		opts := Options{Paranoia: ParanoiaStrict}
		ch := make(chan Finding, 100)
		go RunAttestation(context.Background(), repo, opts, ch)
		findings := collectFindings(ch)

		// Should have INFO findings: API verified, workflow found, SHA256SUMS, cosign
		foundAPIVerified := false
		for _, f := range findings {
			if contains(f.Message, "attestation verified") {
				foundAPIVerified = true
			}
		}
		if !foundAPIVerified {
			t.Errorf("expected API verification INFO finding, got: %+v", findings)
		}
	})

	t.Run("API returns no attestation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
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
			Files:    map[string][]byte{},
		}
		opts := Options{Paranoia: ParanoiaStrict}
		ch := make(chan Finding, 100)
		go RunAttestation(context.Background(), repo, opts, ch)
		findings := collectFindings(ch)

		foundNoAttestation := false
		for _, f := range findings {
			if contains(f.Message, "No GitHub attestation found") && f.Severity == SevMedium {
				foundNoAttestation = true
			}
		}
		if !foundNoAttestation {
			t.Errorf("expected MEDIUM finding for no attestation, got: %+v", findings)
		}
	})
}
