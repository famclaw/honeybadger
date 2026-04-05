// Package engine contains the core business logic for honeybadger:
// verdict computation, tier/sandbox detection, and update verification.
package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/scanner/attestation"
	"github.com/famclaw/honeybadger/internal/scanner/cve"
	"github.com/famclaw/honeybadger/internal/scanner/meta"
	"github.com/famclaw/honeybadger/internal/scanner/secrets"
	"github.com/famclaw/honeybadger/internal/scanner/supplychain"
)

// ComputeVerdict determines the final verdict from findings, paranoia, and optional LLM verdict.
func ComputeVerdict(findings []scan.Finding, paranoia scan.ParanoiaLevel, llmVerdict *report.LLMVerdict) (string, string, string) {
	if paranoia == scan.ParanoiaOff {
		return "PASS", "Scanning disabled (paranoia=off)", ""
	}

	threshold, ok := scan.BlockThresholds[paranoia]
	if !ok {
		threshold = scan.SevHigh // default to family
	}

	thresholdRank := scan.SeverityRank(threshold)
	warnRank := thresholdRank - 1

	verdict := "PASS"
	reasoning := "No findings at or above threshold"
	keyFinding := ""
	maxSevRank := 0

	for _, f := range findings {
		rank := scan.SeverityRank(f.Severity)
		if rank > maxSevRank {
			maxSevRank = rank
			keyFinding = f.Message
		}

		if rank >= thresholdRank {
			verdict = "FAIL"
			reasoning = fmt.Sprintf("Finding at %s severity meets or exceeds %s threshold", f.Severity, threshold)
		} else if rank >= warnRank && verdict != "FAIL" {
			verdict = "WARN"
			reasoning = fmt.Sprintf("Finding at %s severity is one level below %s threshold", f.Severity, threshold)
		}
	}

	// Strict and paranoid: WARN becomes FAIL
	if (paranoia == scan.ParanoiaStrict || paranoia == scan.ParanoiaParanoid) && verdict == "WARN" {
		verdict = "FAIL"
		reasoning = reasoning + " (escalated: strict/paranoid mode treats WARN as FAIL)"
	}

	// Combine with LLM verdict (take the worse one)
	if llmVerdict != nil {
		llmRank := VerdictRank(llmVerdict.Verdict)
		rulesRank := VerdictRank(verdict)
		if llmRank > rulesRank {
			verdict = llmVerdict.Verdict
			reasoning = fmt.Sprintf("LLM verdict: %s", llmVerdict.Reasoning)
			if llmVerdict.KeyFinding != "" {
				keyFinding = llmVerdict.KeyFinding
			}
		}
	}

	return verdict, reasoning, keyFinding
}

// VerdictRank returns a numeric ranking for verdict comparison.
func VerdictRank(v string) int {
	switch v {
	case "PASS":
		return 0
	case "WARN":
		return 1
	case "FAIL":
		return 2
	default:
		return -1
	}
}

// ExitCodeForVerdict maps verdict to exit code.
func ExitCodeForVerdict(verdict string) int {
	switch verdict {
	case "PASS":
		return 0
	case "WARN":
		return 1
	case "FAIL":
		return 2
	default:
		return 3
	}
}

// DetectTier determines if we're online or offline.
func DetectTier(offline bool) string {
	if offline {
		return "offline"
	}

	// Try HEAD to GitHub API
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodHead, "https://api.github.com", nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return "online"
		}
	}

	// Fallback: TCP dial to dns.google:443
	conn, err := net.DialTimeout("tcp", "dns.google:443", 5*time.Second)
	if err == nil {
		conn.Close()
		return "online"
	}

	return "offline"
}

// IsTermux detects the Termux environment.
func IsTermux() bool {
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	_, err := os.Stat("/data/data/com.termux")
	return err == nil
}

// DetectSandbox checks for available sandbox mechanisms.
func DetectSandbox() (available bool, sandboxType, reason string) {
	// Check Docker
	if _, err := exec.LookPath("docker"); err == nil {
		return true, "docker", "Docker available"
	}

	// Check macOS sandbox-exec
	if runtime.GOOS == "darwin" {
		return true, "sandbox-exec", "macOS sandbox-exec available"
	}

	return false, "none", "No sandbox mechanism detected"
}

// ProgressEvent creates a progress event map.
func ProgressEvent(phase, message string) map[string]any {
	return map[string]any{
		"type":    "progress",
		"phase":   phase,
		"message": message,
	}
}

// ComputeRepoHash computes a SHA256 hash of all repo file contents in sorted order.
func ComputeRepoHash(repo *fetch.Repo) string {
	paths := make([]string, 0, len(repo.Files))
	for p := range repo.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write(repo.Files[p])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CheckToolHash searches for MCP tool registrations and compares hash.
func CheckToolHash(repo *fetch.Repo, expectedHash string) []scan.Finding {
	toolPatterns := []*regexp.Regexp{
		regexp.MustCompile(`mcp\.NewTool\(\s*"([^"]+)"`),
		regexp.MustCompile(`server\.AddTool\(\s*"([^"]+)"`),
		regexp.MustCompile(`tool\.New\(\s*"([^"]+)"`),
	}

	toolNames := make(map[string]bool)
	for path, content := range repo.Files {
		_ = path
		src := string(content)
		for _, pat := range toolPatterns {
			matches := pat.FindAllStringSubmatch(src, -1)
			for _, m := range matches {
				if len(m) > 1 {
					toolNames[m[1]] = true
				}
			}
		}
	}

	if len(toolNames) == 0 {
		return []scan.Finding{{
			Type:     "finding",
			Severity: scan.SevLow,
			Check:    "tool-hash",
			Message:  "Could not extract tool registrations from source; tool hash verification skipped",
		}}
	}

	// Sort and hash tool names
	names := make([]string, 0, len(toolNames))
	for n := range toolNames {
		names = append(names, n)
	}
	sort.Strings(names)

	toolJSON, _ := json.Marshal(names)
	h := sha256.Sum256(toolJSON)
	actualHash := fmt.Sprintf("%x", h[:])

	if actualHash != expectedHash {
		return []scan.Finding{{
			Type:     "finding",
			Severity: scan.SevHigh,
			Check:    "tool-hash",
			Message:  fmt.Sprintf("Tool hash mismatch: expected %s, got %s", expectedHash, actualHash),
		}}
	}

	return nil
}

// BuildScannerList returns the scanners to run based on paranoia level.
func BuildScannerList(opts scan.Options) []scan.ScanFunc {
	switch opts.Paranoia {
	case scan.ParanoiaOff:
		return nil
	case scan.ParanoiaMinimal:
		return []scan.ScanFunc{secrets.Run, cve.Run}
	case scan.ParanoiaFamily:
		return []scan.ScanFunc{secrets.Run, cve.Run, supplychain.Run, meta.Run}
	case scan.ParanoiaStrict:
		return []scan.ScanFunc{secrets.Run, cve.Run, supplychain.Run, meta.Run, attestation.Run}
	case scan.ParanoiaParanoid:
		return []scan.ScanFunc{secrets.Run, cve.Run, supplychain.Run, meta.Run, attestation.Run}
	default:
		// Default to family
		return []scan.ScanFunc{secrets.Run, cve.Run, supplychain.Run, meta.Run}
	}
}
