package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestRunCVE_WithVulnerabilities(t *testing.T) {
	// Disable rate-limiting in tests.
	origDelay := osvFetchDelay
	osvFetchDelay = 0
	defer func() { osvFetchDelay = origDelay }()

	// Set up mock osv.dev server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		resp := osvBatchResponse{
			Results: []osvResult{
				{
					Vulns: []osvVuln{
						{
							ID:      "GHSA-1234-5678-9abc",
							Summary: "Remote code injection in lodash",
							Severity: []struct {
								Type  string `json:"type"`
								Score string `json:"score"`
							}{
								{Type: "CVSS_V3", Score: "9.8"},
							},
							Affected: []struct {
								Ranges []struct {
									Events []struct {
										Fixed string `json:"fixed"`
									} `json:"events"`
								} `json:"ranges"`
							}{
								{
									Ranges: []struct {
										Events []struct {
											Fixed string `json:"fixed"`
										} `json:"events"`
									}{
										{
											Events: []struct {
												Fixed string `json:"fixed"`
											}{
												{Fixed: "4.17.21"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override endpoint
	origEndpoint := osvEndpoint
	osvEndpoint = server.URL
	defer func() { osvEndpoint = origEndpoint }()

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"requirements.txt": []byte("requests==2.25.0\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, scan.Options{}, out, nil)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}

	f := findings[0]
	if f.Type != "cve" {
		t.Errorf("expected type 'cve', got %q", f.Type)
	}
	if f.ID != "GHSA-1234-5678-9abc" {
		t.Errorf("expected ID 'GHSA-1234-5678-9abc', got %q", f.ID)
	}
	if f.Severity != scan.SevCritical {
		t.Errorf("expected severity CRITICAL for score 9.8, got %q", f.Severity)
	}
	if f.FixedIn != "4.17.21" {
		t.Errorf("expected fixed_in '4.17.21', got %q", f.FixedIn)
	}
	if f.Package != "requests" {
		t.Errorf("expected package 'requests', got %q", f.Package)
	}
}

func TestRunCVE_FollowUpFetch(t *testing.T) {
	// Disable rate-limiting in tests.
	origDelay := osvFetchDelay
	osvFetchDelay = 0
	defer func() { osvFetchDelay = origDelay }()

	// Set up mock osv.dev server that returns abbreviated batch + full record on /v1/vulns/{id}.
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Handle /v1/vulns/{id} follow-up endpoint.
		if r.Method == "GET" && len(r.URL.Path) > len("/v1/vulns/") {
			rec := osvVuln{
				ID:      "GHSA-1234-5678-9abc",
				Summary: "Remote code injection in lodash",
				Severity: []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: "9.8"},
				},
				Affected: []struct {
					Ranges []struct {
						Events []struct {
							Fixed string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				}{
					{
						Ranges: []struct {
							Events []struct {
								Fixed string `json:"fixed"`
							} `json:"events"`
						}{
							{
								Events: []struct {
									Fixed string `json:"fixed"`
								}{
									{Fixed: "4.17.21"},
								},
							},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rec)
			return
		}

		// Batch endpoint returns abbreviated record (no CVSS).
		resp := osvBatchResponse{
			Results: []osvResult{
				{
					Vulns: []osvVuln{
						{
							ID:       "GHSA-1234-5678-9abc",
							Summary:  "",
							Severity: nil,
							Affected: nil,
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Configure mock server to serve both batch and /v1/vulns/{id}.
	origEndpoint := osvEndpoint
	osvEndpoint = server.URL
	origAPIBase := osvAPIBase
	osvAPIBase = server.URL
	defer func() {
		osvEndpoint = origEndpoint
		osvAPIBase = origAPIBase
	}()

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"requirements.txt": []byte("requests==2.25.0\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, scan.Options{}, out, nil)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}

	f := findings[0]
	if f.Type != "cve" {
		t.Errorf("expected type 'cve', got %q", f.Type)
	}
	if f.ID != "GHSA-1234-5678-9abc" {
		t.Errorf("expected ID 'GHSA-1234-5678-9abc', got %q", f.ID)
	}
	if f.Severity != scan.SevCritical {
		t.Errorf("expected severity CRITICAL for score 9.8, got %q", f.Severity)
	}
	if f.FixedIn != "4.17.21" {
		t.Errorf("expected fixed_in '4.17.21', got %q", f.FixedIn)
	}
	if f.Package != "requests" {
		t.Errorf("expected package 'requests', got %q", f.Package)
	}

	// Verify follow-up fetch was called.
	if requestCount != 2 {
		t.Errorf("expected 2 HTTP requests (batch + follow-up), got %d", requestCount)
	}
}

func TestRunCVE_FollowUpFetchFallback(t *testing.T) {
	// Disable rate-limiting in tests.
	origDelay := osvFetchDelay
	osvFetchDelay = 0
	defer func() { osvFetchDelay = origDelay }()

	// Set up mock osv.dev server that returns abbreviated batch but fails on follow-up.
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Handle /v1/vulns/{id} follow-up endpoint - return 404.
		if r.Method == "GET" && len(r.URL.Path) > len("/v1/vulns/") {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"Vulnerability not found"}`))
			return
		}

		// Batch endpoint returns abbreviated record (no CVSS).
		resp := osvBatchResponse{
			Results: []osvResult{
				{
					Vulns: []osvVuln{
						{
							ID:       "GHSA-1234-5678-9abc",
							Summary:  "",
							Severity: nil,
							Affected: nil,
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Configure mock server to serve both batch and /v1/vulns/{id}.
	origEndpoint := osvEndpoint
	osvEndpoint = server.URL
	origAPIBase := osvAPIBase
	osvAPIBase = server.URL
	defer func() {
		osvEndpoint = origEndpoint
		osvAPIBase = origAPIBase
	}()

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"requirements.txt": []byte("requests==2.25.0\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, scan.Options{}, out, nil)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}

	f := findings[0]
	if f.Type != "cve" {
		t.Errorf("expected type 'cve', got %q", f.Type)
	}
	if f.Severity != scan.SevMedium {
		t.Errorf("expected severity MEDIUM (fallback) when follow-up fails, got %q", f.Severity)
	}

	// Verify both requests were made.
	if requestCount != 2 {
		t.Errorf("expected 2 HTTP requests (batch + follow-up), got %d", requestCount)
	}
}

func TestRunCVE_EmptyDeps(t *testing.T) {
	// Disable rate-limiting in tests.
	origDelay := osvFetchDelay
	osvFetchDelay = 0
	defer func() { osvFetchDelay = origDelay }()

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"main.go": []byte("package main\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, scan.Options{}, out, nil)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for empty deps, got %d", len(findings))
	}
}

func TestRunCVE_OfflineMode(t *testing.T) {
	// Disable rate-limiting in tests.
	origDelay := osvFetchDelay
	osvFetchDelay = 0
	defer func() { osvFetchDelay = origDelay }()

	// In offline mode, no HTTP call should be made at all
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("HTTP call should not be made in offline mode")
	}))
	defer server.Close()

	origEndpoint := osvEndpoint
	osvEndpoint = server.URL
	defer func() { osvEndpoint = origEndpoint }()

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"requirements.txt": []byte("requests==2.25.0\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, scan.Options{Offline: true}, out, nil)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings in offline mode, got %d", len(findings))
	}
}

func TestRunCVE_NoVulnerabilities(t *testing.T) {
	// Disable rate-limiting in tests.
	origDelay := osvFetchDelay
	osvFetchDelay = 0
	defer func() { osvFetchDelay = origDelay }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{
			Results: []osvResult{
				{Vulns: nil},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	origEndpoint := osvEndpoint
	osvEndpoint = server.URL
	defer func() { osvEndpoint = origEndpoint }()

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"requirements.txt": []byte("requests==2.31.0\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, scan.Options{}, out, nil)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings when no vulns, got %d", len(findings))
	}
}

func TestMapOSVSeverity(t *testing.T) {
	tests := []struct {
		name     string
		score    string
		expected string
	}{
		{"critical", "9.8", scan.SevCritical},
		{"high", "7.5", scan.SevHigh},
		{"medium", "5.0", scan.SevMedium},
		{"low", "2.0", scan.SevLow},
		{"no_score", "", scan.SevMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := osvVuln{}
			if tt.score != "" {
				vuln.Severity = []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				}{
					{Type: "CVSS_V3", Score: tt.score},
				}
			}
			got := mapOSVSeverity(vuln)
			if got != tt.expected {
				t.Errorf("mapOSVSeverity(score=%q) = %q, want %q", tt.score, got, tt.expected)
			}
		})
	}
}

func TestExtractFixedVersion(t *testing.T) {
	vuln := osvVuln{
		Affected: []struct {
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
		}{
			{
				Ranges: []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				}{
					{
						Events: []struct {
							Fixed string `json:"fixed"`
						}{
							{Fixed: ""},
							{Fixed: "2.31.1"},
						},
					},
				},
			},
		},
	}

	got := extractFixedVersion(vuln)
	if got != "2.31.1" {
		t.Errorf("extractFixedVersion = %q, want %q", got, "2.31.1")
	}
}
