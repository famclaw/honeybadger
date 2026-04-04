package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/store"
)

// Version is injected at build time via ldflags.
var Version = "dev"

func main() {
	// Read environment variables
	llmEndpoint := envOrDefault("HONEYBADGER_LLM", "")
	llmKey := envOrDefault("HONEYBADGER_LLM_KEY", "")
	llmModel := envOrDefault("HONEYBADGER_LLM_MODEL", "")
	githubToken := envOrDefault("GITHUB_TOKEN", "")
	gitlabToken := envOrDefault("GITLAB_TOKEN", "")

	// Define flags
	paranoia := flag.String("paranoia", "family", "paranoia level: off|minimal|family|strict|paranoid")
	format := flag.String("format", "ndjson", "output format: ndjson|text")
	llm := flag.String("llm", llmEndpoint, "LLM endpoint override")
	db := flag.String("db", "", "SQLite path for audit trail")
	installedSHA := flag.String("installed-sha", "", "installed commit SHA")
	installedToolHash := flag.String("installed-tool-hash", "", "installed tool hash")
	force := flag.Bool("force", false, "force scan even if already audited")
	offline := flag.Bool("offline", false, "offline mode -- skip network checks")
	path := flag.String("path", "", "subdirectory within repo")
	// --mcp-server and --version are handled before flag.Parse (see below)

	// Extract subcommand before parsing flags.
	// This allows: honeybadger scan <url> --paranoia strict
	args := os.Args[1:]
	subcommand := ""
	var repoURL string
	var remaining []string

	for i, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Println("honeybadger", Version)
			os.Exit(0)
		}
		if arg == "--mcp-server" || arg == "-mcp-server" {
			if err := serveMCP(); err != nil {
				fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if arg == "scan" && subcommand == "" {
			subcommand = "scan"
			// Next non-flag arg is the repo URL
			for j := i + 1; j < len(args); j++ {
				if !strings.HasPrefix(args[j], "-") && repoURL == "" {
					repoURL = args[j]
				} else {
					remaining = append(remaining, args[j])
				}
			}
			break
		}
	}

	if subcommand != "scan" {
		fmt.Fprintln(os.Stderr, "usage: honeybadger scan <repo-url> [flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if repoURL == "" {
		fmt.Fprintln(os.Stderr, "error: scan requires a <repo-url> argument")
		os.Exit(1)
	}

	// Parse remaining flags after extracting subcommand and URL
	if err := flag.CommandLine.Parse(remaining); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	exitCode, err := run(repoURL, *paranoia, *format, *llm, *db, *installedSHA, *installedToolHash, *force, *offline, *path, llmKey, llmModel, githubToken, gitlabToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func run(repoURL, paranoiaStr, format, llmEndpoint, dbPath, installedSHA, installedToolHash string, force, offline bool, subPath, llmKey, llmModel, githubToken, gitlabToken string) (int, error) {
	start := time.Now()
	ctx := context.Background()

	// 1. Parse paranoia level
	paranoia, err := scan.ParseParanoia(paranoiaStr)
	if err != nil {
		return 1, fmt.Errorf("invalid paranoia: %w", err)
	}

	// 2. Select emitter
	var emitter report.Emitter
	switch format {
	case "text":
		emitter = report.NewTextEmitter(os.Stdout)
	default:
		emitter = report.NewNDJSONEmitter(os.Stdout)
	}
	defer emitter.Close()

	// 3. Handle --force
	if force {
		result := map[string]any{
			"type":      "result",
			"verdict":   "PASS",
			"reasoning": "Scan bypassed via --force flag",
		}
		emitter.Emit(result) //nolint:errcheck
		return 0, nil
	}

	// 4. Tier detection
	tier := detectTier(offline)

	// 5. Sandbox detection and event
	sandboxAvailable, sandboxType, reason := detectSandbox()
	effectiveParanoia := string(paranoia)

	if isTermux() {
		sandboxAvailable = false
		reason = "Termux does not support sandboxing"
		if scan.SeverityRank(string(paranoia)) > scan.SeverityRank(string(scan.ParanoiaFamily)) {
			effectiveParanoia = string(scan.ParanoiaFamily)
		}
	}

	emitter.Emit(map[string]any{ //nolint:errcheck
		"type":               "sandbox",
		"available":          sandboxAvailable,
		"reason":             reason,
		"sandbox_type":       sandboxType,
		"effective_paranoia": effectiveParanoia,
	})

	// 6. Fetch repo
	emitter.Emit(progressEvent("fetch", "Fetching repository...")) //nolint:errcheck

	fetcher, err := fetch.Route(repoURL)
	if err != nil {
		return 1, fmt.Errorf("routing: %w", err)
	}

	fetchOpts := fetch.FetchOptions{
		GithubToken: githubToken,
		GitlabToken: gitlabToken,
		SubPath:     subPath,
	}

	repo, err := fetcher.Fetch(ctx, repoURL, fetchOpts)
	if err != nil {
		return 1, fmt.Errorf("fetching repo: %w", err)
	}

	// 13a. Update verification: --installed-sha
	if installedSHA != "" {
		archiveHash := computeRepoHash(repo)
		if archiveHash == installedSHA {
			result := map[string]any{
				"type":      "result",
				"verdict":   "PASS",
				"reasoning": "Installed SHA matches fetched repository content",
			}
			emitter.Emit(result) //nolint:errcheck
			return 0, nil
		}
		// SHA differs, proceed with full scan
	}

	// 7. Run scanners
	effectiveParanoiaLevel, _ := scan.ParseParanoia(effectiveParanoia)

	scanOpts := scan.Options{
		Paranoia:          effectiveParanoiaLevel,
		Format:            format,
		LLMEndpoint:       llmEndpoint,
		LLMKey:            llmKey,
		LLMModel:          llmModel,
		DBPath:            dbPath,
		InstalledSHA:      installedSHA,
		InstalledToolHash: installedToolHash,
		Force:             force,
		Offline:           offline,
		RepoPath:          subPath,
		GithubToken:       githubToken,
		GitlabToken:       gitlabToken,
	}

	emitter.Emit(progressEvent("scan", "Running security scanners...")) //nolint:errcheck

	findings := scan.RunAll(ctx, repo, scanOpts)

	var allFindings []scan.Finding
	for f := range findings {
		emitter.Emit(f) //nolint:errcheck
		allFindings = append(allFindings, f)
	}

	// 13b. Update verification: --installed-tool-hash
	if installedToolHash != "" {
		toolFindings := checkToolHash(repo, installedToolHash)
		for _, f := range toolFindings {
			emitter.Emit(f) //nolint:errcheck
			allFindings = append(allFindings, f)
		}
	}

	// 8. Emit health event
	emitter.Emit(map[string]any{ //nolint:errcheck
		"type":                    "health",
		"stars":                   repo.Health.Stars,
		"contributors":            repo.Health.Contributors,
		"age_days":                repo.Health.AgeDays,
		"last_commit_days":        repo.Health.LastCommitDays,
		"has_license":             repo.Health.HasLicense,
		"has_security_md":         repo.Health.HasSecurityMD,
		"has_signed_commits":      repo.Health.HasSignedCommits,
		"recent_ownership_change": repo.Health.RecentOwnerChange,
		"issues_mentioning_risk":  repo.Health.IssuesMentioningRisk,
	})

	// 9. LLM verdict
	var llmVerdict *report.LLMVerdict
	llmUsed := false
	if paranoia >= scan.ParanoiaFamily && llmEndpoint != "" {
		emitter.Emit(progressEvent("llm", "Asking LLM for verdict...")) //nolint:errcheck

		llmOpts := report.LLMOptions{
			Paranoia: string(paranoia),
			Platform: runtime.GOOS,
			Tier:     tier,
		}
		prompt := report.AssembleLLMPrompt(repo, allFindings, llmOpts)
		v, err := report.CallLLM(ctx, prompt, llmEndpoint, llmKey, llmModel)
		if err != nil {
			// LLM failure is non-fatal; emit a warning and continue
			emitter.Emit(progressEvent("llm", fmt.Sprintf("LLM call failed: %v", err))) //nolint:errcheck
		} else if v != nil {
			llmVerdict = v
			llmUsed = true
		}
	}

	// 10. Compute final verdict
	verdict, reasoning, keyFinding := computeVerdict(allFindings, paranoia, llmVerdict)

	// Count findings by severity
	findingCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	cveCount := 0
	cveMaxSev := ""
	for _, f := range allFindings {
		switch f.Severity {
		case scan.SevCritical:
			findingCounts["critical"]++
		case scan.SevHigh:
			findingCounts["high"]++
		case scan.SevMedium:
			findingCounts["medium"]++
		case scan.SevLow:
			findingCounts["low"]++
		case scan.SevInfo:
			findingCounts["info"]++
		}
		if f.Type == "cve" {
			cveCount++
			if cveMaxSev == "" || scan.SeverityRank(f.Severity) > scan.SeverityRank(cveMaxSev) {
				cveMaxSev = f.Severity
			}
		}
	}

	// 11. Emit final result
	result := map[string]any{
		"type":               "result",
		"verdict":            verdict,
		"reasoning":          reasoning,
		"key_finding":        keyFinding,
		"finding_counts":     findingCounts,
		"cve_count":          cveCount,
		"cve_max_severity":   cveMaxSev,
		"attested":           false,
		"llm_model":          llmModel,
		"llm_used":           llmUsed,
		"paranoia":           string(paranoia),
		"effective_paranoia": effectiveParanoia,
		"tier":               tier,
		"sandbox":            sandboxType,
		"scanned_at":         time.Now().UTC().Format(time.RFC3339),
		"duration_ms":        time.Since(start).Milliseconds(),
	}
	emitter.Emit(result) //nolint:errcheck

	// Write audit if --db provided
	if dbPath != "" {
		if err := store.WriteAudit(dbPath, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: audit write failed: %v\n", err)
		}
	}

	// 12. Exit code
	return exitCodeForVerdict(verdict), nil
}

// computeVerdict determines the final verdict from findings, paranoia, and optional LLM verdict.
func computeVerdict(findings []scan.Finding, paranoia scan.ParanoiaLevel, llmVerdict *report.LLMVerdict) (string, string, string) {
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
		llmRank := verdictRank(llmVerdict.Verdict)
		rulesRank := verdictRank(verdict)
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

// verdictRank returns a numeric ranking for verdict comparison.
func verdictRank(v string) int {
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

// exitCodeForVerdict maps verdict to exit code.
func exitCodeForVerdict(verdict string) int {
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

// detectTier determines if we're online or offline.
func detectTier(offline bool) string {
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

// isTermux detects the Termux environment.
func isTermux() bool {
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	_, err := os.Stat("/data/data/com.termux")
	return err == nil
}

// detectSandbox checks for available sandbox mechanisms.
func detectSandbox() (available bool, sandboxType, reason string) {
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

// progressEvent creates a progress event map.
func progressEvent(phase, message string) map[string]any {
	return map[string]any{
		"type":    "progress",
		"phase":   phase,
		"message": message,
	}
}

// computeRepoHash computes a SHA256 hash of all repo file contents in sorted order.
func computeRepoHash(repo *fetch.Repo) string {
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

// checkToolHash searches for MCP tool registrations and compares hash.
func checkToolHash(repo *fetch.Repo, expectedHash string) []scan.Finding {
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

func serveMCP() error {
	s := newMCPServer()
	return server.ServeStdio(s)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
