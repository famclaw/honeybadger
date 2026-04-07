package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/famclaw/honeybadger/internal/engine"
	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/rules"
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
	llmTimeout := flag.Duration("llm-timeout", 5*time.Minute, "LLM call timeout (default 5m)")
	rulesDir := flag.String("rules-dir", "", "custom rules directory")
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

	exitCode, err := run(repoURL, *paranoia, *format, *llm, *db, *installedSHA, *installedToolHash, *force, *offline, *path, llmKey, llmModel, githubToken, gitlabToken, *llmTimeout, *rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func run(repoURL, paranoiaStr, format, llmEndpoint, dbPath, installedSHA, installedToolHash string, force, offline bool, subPath, llmKey, llmModel, githubToken, gitlabToken string, llmTimeout time.Duration, rulesDir string) (int, error) {
	start := time.Now()
	ctx := context.Background()

	// Load rules
	dir := rulesDir
	if dir == "" {
		dir = os.Getenv("HONEYBADGER_RULES_DIR")
	}
	rs, err := rules.Load(dir)
	if err != nil {
		// Embedded rule errors are bugs; user rule errors are config mistakes.
		// Both are fatal — an incomplete rule set could silently miss threats.
		return 1, fmt.Errorf("loading rules: %w", err)
	}

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
	tier := engine.DetectTier(offline)

	// 5. Sandbox detection and event
	sandboxAvailable, sandboxType, reason := engine.DetectSandbox()
	effectiveParanoia := string(paranoia)

	if engine.IsTermux() {
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
	emitter.Emit(engine.ProgressEvent("fetch", "Fetching repository...")) //nolint:errcheck

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
		archiveHash := engine.ComputeRepoHash(repo)
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
		LLMTimeout:        llmTimeout,
		Rules:             rs,
	}

	emitter.Emit(engine.ProgressEvent("scan", "Running security scanners...")) //nolint:errcheck

	scanners := engine.BuildScannerList(scanOpts)
	findings := scan.RunAll(ctx, repo, scanOpts, scanners)

	var allFindings []scan.Finding
	for f := range findings {
		emitter.Emit(f) //nolint:errcheck
		allFindings = append(allFindings, f)
	}

	// 13b. Update verification: --installed-tool-hash
	if installedToolHash != "" {
		toolFindings := engine.CheckToolHash(repo, installedToolHash)
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
		emitter.Emit(engine.ProgressEvent("llm", "Asking LLM for verdict...")) //nolint:errcheck

		llmCtx, llmCancel := context.WithTimeout(ctx, llmTimeout)
		defer llmCancel()

		llmOpts := report.LLMOptions{
			Paranoia: string(paranoia),
			Platform: runtime.GOOS,
			Tier:     tier,
		}
		prompt := report.AssembleLLMPrompt(repo, allFindings, llmOpts)
		v, err := report.CallLLM(llmCtx, prompt, llmEndpoint, llmKey, llmModel)
		if err != nil {
			msg := fmt.Sprintf("LLM call failed: %v", err)
			if llmCtx.Err() == context.DeadlineExceeded {
				msg = fmt.Sprintf("LLM timed out after %v — using static findings only", llmTimeout)
			}
			emitter.Emit(engine.ProgressEvent("llm", msg)) //nolint:errcheck
		} else if v != nil {
			llmVerdict = v
			llmUsed = true
		}
	}

	// 10. Compute final verdict
	verdict, reasoning, keyFinding := engine.ComputeVerdict(allFindings, paranoia, llmVerdict)

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
	return engine.ExitCodeForVerdict(verdict), nil
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
