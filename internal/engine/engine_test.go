package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestComputeVerdict(t *testing.T) {
	tests := []struct {
		name      string
		findings  []scan.Finding
		paranoia  scan.ParanoiaLevel
		llm       *report.LLMVerdict
		wantV     string
		wantHasKF bool // whether key_finding should be non-empty
	}{
		{
			name:     "no findings family -> PASS",
			findings: nil,
			paranoia: scan.ParanoiaFamily,
			wantV:    "PASS",
		},
		{
			name:     "paranoia off -> PASS regardless",
			findings: []scan.Finding{{Type: "finding", Severity: scan.SevCritical, Check: "test", Message: "crit"}},
			paranoia: scan.ParanoiaOff,
			wantV:    "PASS",
		},
		{
			name: "HIGH finding at family -> FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevHigh, Check: "secrets", Message: "leaked key"},
			},
			paranoia:  scan.ParanoiaFamily,
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "MEDIUM finding at family -> WARN",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevMedium, Check: "meta", Message: "no license"},
			},
			paranoia:  scan.ParanoiaFamily,
			wantV:     "WARN",
			wantHasKF: true,
		},
		{
			name: "LOW finding at family -> PASS",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevLow, Check: "meta", Message: "minor issue"},
			},
			paranoia:  scan.ParanoiaFamily,
			wantV:     "PASS",
			wantHasKF: true,
		},
		{
			name: "CRITICAL finding at minimal -> FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevCritical, Check: "secrets", Message: "critical secret"},
			},
			paranoia:  scan.ParanoiaMinimal,
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "HIGH finding at minimal -> WARN",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevHigh, Check: "secrets", Message: "high secret"},
			},
			paranoia:  scan.ParanoiaMinimal,
			wantV:     "WARN",
			wantHasKF: true,
		},
		{
			name: "MEDIUM finding at strict -> FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevMedium, Check: "supply", Message: "suspicious pattern"},
			},
			paranoia:  scan.ParanoiaStrict,
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "LOW finding at strict -> WARN escalated to FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevLow, Check: "meta", Message: "low issue"},
			},
			paranoia:  scan.ParanoiaStrict,
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "LOW finding at paranoid -> FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevLow, Check: "meta", Message: "low issue"},
			},
			paranoia:  scan.ParanoiaParanoid,
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "INFO finding at paranoid -> WARN escalated to FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevInfo, Check: "meta", Message: "info"},
			},
			paranoia:  scan.ParanoiaParanoid,
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name:     "LLM overrides PASS to FAIL",
			findings: nil,
			paranoia: scan.ParanoiaFamily,
			llm: &report.LLMVerdict{
				Verdict:    "FAIL",
				Reasoning:  "LLM found issue",
				KeyFinding: "suspicious code",
			},
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "LLM PASS does not override rules FAIL",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevHigh, Check: "secrets", Message: "leaked key"},
			},
			paranoia: scan.ParanoiaFamily,
			llm: &report.LLMVerdict{
				Verdict:   "PASS",
				Reasoning: "LLM thinks its ok",
			},
			wantV:     "FAIL",
			wantHasKF: true,
		},
		{
			name: "multiple findings - worst wins",
			findings: []scan.Finding{
				{Type: "finding", Severity: scan.SevLow, Check: "meta", Message: "low"},
				{Type: "finding", Severity: scan.SevCritical, Check: "secrets", Message: "critical secret"},
				{Type: "finding", Severity: scan.SevMedium, Check: "supply", Message: "medium"},
			},
			paranoia:  scan.ParanoiaFamily,
			wantV:     "FAIL",
			wantHasKF: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, reasoning, keyFinding := ComputeVerdict(tt.findings, tt.paranoia, tt.llm)
			if verdict != tt.wantV {
				t.Errorf("verdict = %q, want %q (reasoning: %s)", verdict, tt.wantV, reasoning)
			}
			if tt.wantHasKF && keyFinding == "" {
				t.Errorf("expected non-empty key_finding, got empty")
			}
		})
	}
}

func TestIsTermux(t *testing.T) {
	// Save and restore env
	orig := os.Getenv("TERMUX_VERSION")
	defer os.Setenv("TERMUX_VERSION", orig)

	// Set TERMUX_VERSION
	os.Setenv("TERMUX_VERSION", "0.118")
	if !IsTermux() {
		t.Error("expected IsTermux()=true when TERMUX_VERSION is set")
	}

	// Unset
	os.Unsetenv("TERMUX_VERSION")
	// IsTermux may still return true if /data/data/com.termux exists
	if _, err := os.Stat("/data/data/com.termux"); err != nil {
		if IsTermux() {
			t.Error("expected IsTermux()=false when TERMUX_VERSION unset and path doesn't exist")
		}
	}
}

func TestExitCodeForVerdict(t *testing.T) {
	tests := []struct {
		verdict  string
		wantCode int
	}{
		{"PASS", 0},
		{"WARN", 1},
		{"FAIL", 2},
		{"UNKNOWN", 3},
		{"", 3},
	}

	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			got := ExitCodeForVerdict(tt.verdict)
			if got != tt.wantCode {
				t.Errorf("ExitCodeForVerdict(%q) = %d, want %d", tt.verdict, got, tt.wantCode)
			}
		})
	}
}

func TestVerdictRank(t *testing.T) {
	tests := []struct {
		verdict string
		want    int
	}{
		{"PASS", 0},
		{"WARN", 1},
		{"FAIL", 2},
		{"OTHER", -1},
	}

	for _, tt := range tests {
		t.Run(tt.verdict, func(t *testing.T) {
			got := VerdictRank(tt.verdict)
			if got != tt.want {
				t.Errorf("VerdictRank(%q) = %d, want %d", tt.verdict, got, tt.want)
			}
		})
	}
}

func TestCheckToolHash(t *testing.T) {
	t.Run("no tools found", func(t *testing.T) {
		repo := &fetch.Repo{
			Files: map[string][]byte{
				"main.go": []byte("package main\nfunc main() {}"),
			},
		}
		findings := CheckToolHash(repo, "somehash")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != scan.SevLow {
			t.Errorf("expected LOW severity, got %s", findings[0].Severity)
		}
	})

	t.Run("tool hash mismatch", func(t *testing.T) {
		repo := &fetch.Repo{
			Files: map[string][]byte{
				"server.go": []byte(`package main
import "mcp"
func init() {
	mcp.NewTool("calculator")
	mcp.NewTool("weather")
}`),
			},
		}
		findings := CheckToolHash(repo, "wrong-hash")
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != scan.SevHigh {
			t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
		}
	})

	t.Run("tool hash match", func(t *testing.T) {
		repo := &fetch.Repo{
			Files: map[string][]byte{
				"server.go": []byte(`mcp.NewTool("alpha")`),
			},
		}
		// Compute expected hash using same algorithm as CheckToolHash
		names := []string{"alpha"}
		sort.Strings(names)
		toolJSON, _ := json.Marshal(names)
		h := sha256.Sum256(toolJSON)
		correctHash := fmt.Sprintf("%x", h[:])

		findings := CheckToolHash(repo, correctHash)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for matching hash, got %d", len(findings))
		}
	})
}

func TestBuildScannerList_ParanoiaLevels(t *testing.T) {
	tests := []struct {
		paranoia scan.ParanoiaLevel
		want     int
	}{
		{scan.ParanoiaOff, 0},
		{scan.ParanoiaMinimal, 2},
		{scan.ParanoiaFamily, 5},
		{scan.ParanoiaStrict, 6},
		{scan.ParanoiaParanoid, 6},
	}

	for _, tt := range tests {
		t.Run(string(tt.paranoia), func(t *testing.T) {
			scanners := BuildScannerList(scan.Options{Paranoia: tt.paranoia})
			if len(scanners) != tt.want {
				t.Errorf("paranoia=%s: got %d scanners, want %d", tt.paranoia, len(scanners), tt.want)
			}
		})
	}
}

func TestProgressEvent(t *testing.T) {
	ev := ProgressEvent("fetch", "Fetching...")
	if ev["type"] != "progress" {
		t.Errorf("type = %v, want progress", ev["type"])
	}
	if ev["phase"] != "fetch" {
		t.Errorf("phase = %v, want fetch", ev["phase"])
	}
	if ev["message"] != "Fetching..." {
		t.Errorf("message = %v, want Fetching...", ev["message"])
	}
}
