package testfixture

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// osvVuln mirrors the OSV vulnerability structure used by osv.dev responses.
type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

// NewMockOSVServer returns a mock osv.dev server. If hasVulns is true, it
// returns a CRITICAL vulnerability for any query. The caller must call
// Close() on the returned server when done.
func NewMockOSVServer(hasVulns bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp osvBatchResponse
		if hasVulns {
			resp = osvBatchResponse{
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
		} else {
			resp = osvBatchResponse{
				Results: []osvResult{
					{Vulns: nil},
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// NewMockOSVCleanServer returns a mock osv.dev server that always returns
// zero vulnerabilities for any query.
func NewMockOSVCleanServer() *httptest.Server {
	return NewMockOSVServer(false)
}
