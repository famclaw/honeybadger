package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/famclaw/honeybadger/internal/scan"
)

func TestLookupExploitationFixtures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2025-0001"}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2025-0001","epss":"0.97","percentile":"0.99"},{"cve":"CVE-2025-0002","epss":"0.02","percentile":"0.50"}]}`))
	}))
	defer server.Close()
	oldKEV, oldEPSS := kevEndpoint, epssEndpoint
	oldEntries, oldExpiry := kevCache.entries, kevCache.expires
	kevEndpoint, epssEndpoint = server.URL+"/kev", server.URL+"/epss"
	kevCache.entries, kevCache.expires = nil, time.Time{}
	defer func() {
		kevEndpoint, epssEndpoint = oldKEV, oldEPSS
		kevCache.entries, kevCache.expires = oldEntries, oldExpiry
	}()
	got, errs := lookupExploitation(context.Background(), []string{"CVE-2025-0001", "CVE-2025-0002"})
	if len(errs) != 0 {
		t.Fatalf("unexpected feed errors: %v", errs)
	}
	if !got["CVE-2025-0001"].exploited {
		t.Fatal("expected KEV match")
	}
	if e := got["CVE-2025-0001"].epss; e == nil || e.Score != .97 || e.Percentile != .99 {
		t.Fatalf("unexpected EPSS data: %#v", e)
	}
}

func TestLookupExploitationFeedDown(t *testing.T) {
	closedServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closedServer.URL
	closedServer.Close()
	oldKEV, oldEPSS := kevEndpoint, epssEndpoint
	kevEndpoint, epssEndpoint = closedURL+"/kev", closedURL+"/epss"
	oldEntries, oldExpiry := kevCache.entries, kevCache.expires
	kevCache.entries, kevCache.expires = nil, time.Time{}
	defer func() {
		kevEndpoint, epssEndpoint = oldKEV, oldEPSS
		kevCache.entries, kevCache.expires = oldEntries, oldExpiry
	}()
	got, errs := lookupExploitation(context.Background(), []string{"CVE-2025-0001"})
	if len(errs) != 2 {
		t.Fatalf("expected two visible feed failures, got %v", errs)
	}
	if got["CVE-2025-0001"].exploited || got["CVE-2025-0001"].epss != nil {
		t.Fatalf("feed failure should degrade to no intel: %#v", got)
	}
}

func TestGradeSeverity(t *testing.T) {
	epssHigh := &scan.EPSS{Score: .2, Percentile: .9}
	tests := []struct {
		name, base, reason string
		exploited          bool
		epss               *scan.EPSS
		want, wantReason   string
	}{
		{"kev wins", scan.SevLow, "", true, epssHigh, scan.SevCritical, "actively_exploited_kev"},
		{"epss cutoff", scan.SevLow, "", false, epssHigh, scan.SevHigh, "high_epss_percentile"},
		{"cvss retained", scan.SevMedium, "", false, &scan.EPSS{Percentile: .89}, scan.SevMedium, ""},
		{"unknown preserved", scan.SevMedium, "severity_unknown", false, nil, scan.SevMedium, "severity_unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := gradeSeverity(tt.base, tt.reason, tt.exploited, tt.epss)
			if got != tt.want || reason != tt.wantReason {
				t.Fatalf("got %s/%s, want %s/%s", got, reason, tt.want, tt.wantReason)
			}
		})
	}
}
