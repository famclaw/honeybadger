package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
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

// osvEndpoint can be overridden in tests.
var osvEndpoint = osvBatchURL

// RunCVE queries osv.dev for known vulnerabilities in the repo's dependencies.
func RunCVE(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
	defer close(out)
	deps := ParseDeps(repo)
	if len(deps) == 0 || opts.Offline {
		return
	}

	vulns, err := queryOSV(ctx, deps)
	if err != nil {
		out <- Finding{
			Type:     "finding",
			Severity: SevError,
			Check:    "cve",
			Message:  fmt.Sprintf("osv.dev query failed: %v", err),
		}
		return
	}

	for i, result := range vulns.Results {
		if i >= len(deps) {
			break
		}
		dep := deps[i]
		for _, vuln := range result.Vulns {
			out <- Finding{
				Type:      "cve",
				Severity:  mapOSVSeverity(vuln),
				Check:     "cve",
				Package:   dep.Name,
				Version:   dep.Version,
				Ecosystem: dep.Ecosystem,
				ID:        vuln.ID,
				Summary:   vuln.Summary,
				FixedIn:   extractFixedVersion(vuln),
			}
		}
	}
}

// queryOSV sends a batch query to the osv.dev API.
func queryOSV(ctx context.Context, deps []Dependency) (*osvBatchResponse, error) {
	queries := make([]osvQuery, len(deps))
	for i, dep := range deps {
		queries[i].Package.Name = dep.Name
		queries[i].Package.Ecosystem = dep.Ecosystem
		queries[i].Version = dep.Version
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", osvEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv.dev returned status %d", resp.StatusCode)
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// mapOSVSeverity maps a CVSS score string to a severity level.
func mapOSVSeverity(vuln osvVuln) string {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := extractCVSSScore(sev.Score)
			switch {
			case score >= 9.0:
				return SevCritical
			case score >= 7.0:
				return SevHigh
			case score >= 4.0:
				return SevMedium
			case score > 0:
				return SevLow
			}
		}
	}
	// Default if no CVSS score found
	return SevMedium
}

// extractCVSSScore extracts the numeric base score from a CVSS vector string.
// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H has no embedded score,
// so we compute a simplified score from the vector or fall back.
func extractCVSSScore(cvss string) float64 {
	// Some responses include a numeric score directly
	// Try parsing as plain float first
	if f, err := strconv.ParseFloat(cvss, 64); err == nil {
		return f
	}

	// For CVSS vector strings, do simplified scoring based on CIA impact
	if !strings.HasPrefix(cvss, "CVSS:") {
		return 0
	}

	parts := strings.Split(cvss, "/")
	score := 5.0 // base

	for _, part := range parts {
		switch {
		case part == "AV:N":
			score += 1.5
		case part == "AC:L":
			score += 0.5
		case part == "C:H":
			score += 1.0
		case part == "I:H":
			score += 1.0
		case part == "A:H":
			score += 1.0
		case part == "C:N" && strings.Contains(cvss, "I:N") && strings.Contains(cvss, "A:N"):
			return 0 // no impact
		}
	}

	if score > 10.0 {
		score = 10.0
	}
	return score
}

// extractFixedVersion finds the first "fixed" version from the vulnerability's affected ranges.
func extractFixedVersion(vuln osvVuln) string {
	for _, aff := range vuln.Affected {
		for _, r := range aff.Ranges {
			for _, evt := range r.Events {
				if evt.Fixed != "" {
					return evt.Fixed
				}
			}
		}
	}
	return ""
}

// TODO: Integrate golang.org/x/vuln/vulncheck for Go call-graph analysis.
// This would provide reachability-based filtering of CVEs for Go repos,
// only flagging vulnerabilities where the vulnerable code path is actually called.
// For now, osv.dev is the primary CVE data source.
