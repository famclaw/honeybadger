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
	"github.com/famclaw/honeybadger/internal/ignore"
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
	toolManifest := flag.String("tool-manifest", "", "path to MCP tools/list JSON for tool-definition analysis")
	toolBaseline := flag.String("tool-baseline", "", "path to approved MCP tools/list JSON for rug-pull diffing")
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
			// Extract --rules-dir if present in args.
			var mcpRulesDir string
			for j, a := range args {
				if (a == "--rules-dir" || a == "-rules-dir") && j+1 < len(args) {
					mcpRulesDir = args[j+1]
				}
			}
			if err := serveMCP(mcpRulesDir); err != nil {
				fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if arg == "scan" && subcommand == "" {
			subcommand = "scan"
			// Next non-flag arg is the repo URL
			for j := i + 1; j < len(args); j++ {
				if repoURL == "" && (!strings.HasPrefix(args[j], "-") || args[j] == "-") {
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

	cfg := runConfig{
		RepoURL:           repoURL,
		Paranoia:          *paranoia,
		Format:            *format,
		LLMEndpoint:       *llm,
		DBPath:            *db,
		InstalledSHA:      *installedSHA,
		InstalledToolHash: *installedToolHash,
		Force:             *force,
		Offline:           *offline,
		SubPath:           *path,
		LLMKey:            llmKey,
		LLMModel:          llmModel,
		GithubToken:       githubToken,
		GitlabToken:       gitlabToken,
		LLMTimeout:        *llmTimeout,
		RulesDir:          *rulesDir,
		ToolManifest:      *toolManifest,
		ToolBaseline:      *toolBaseline,
	}
	exitCode, err := run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

// runConfig groups the inputs to run() so callers don't have to thread
// 16 positional arguments through the call site.
type runConfig struct {
	RepoURL           string
	Paranoia          string
	Format            string
	LLMEndpoint       string
	DBPath            string
	InstalledSHA      string
	InstalledToolHash string
	Force             bool
	Offline           bool
	SubPath           string
	LLMKey            string
	LLMModel          string
	GithubToken       string
	GitlabToken       string
	LLMTimeout        time.Duration
	RulesDir          string
	ToolManifest      string
	ToolBaseline      string
}

func run(cfg runConfig) (int, error) {
	start := time.Now()
	ctx := context.Background()

	// Load rules
	dir := cfg.RulesDir
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
	paranoia, err := scan.ParseParanoia(cfg.Paranoia)
	if err != nil {
		return 1, fmt.Errorf("invalid paranoia: %w", err)
	}

	// 2. Select emitter
	var emitter report.Emitter
	switch cfg.Format {
	case "text":
		emitter = report.NewTextEmitter(os.Stdout)
	default:
		emitter = report.NewNDJSONEmitter(os.Stdout)
	}
	defer emitter.Close()

	// 3. Handle --force
	if cfg.Force {
		if err := emitter.Emit(engine.ResultEarlyEvent{
			Type:      "result",
			Verdict:   "PASS",
			Reasoning: "Scan bypassed via --force flag",
		}); err != nil {
			return 1, fmt.Errorf("writing output: %w", err)
		}
		return 0, nil
	}

	// 4. Tier detection
	tier := engine.DetectTier(cfg.Offline)

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

	if err := emitter.Emit(engine.SandboxEvent{
		Type:              "sandbox",
		Available:         sandboxAvailable,
		Reason:            reason,
		SandboxType:       sandboxType,
		EffectiveParanoia: effectiveParanoia,
	}); err != nil {
		return 1, fmt.Errorf("writing output: %w", err)
	}

	// 6. Fetch repo
	if err := emitter.Emit(engine.NewProgressEvent("fetch", "Fetching repository...")); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write progress: %v\n", err)
	}

	fetcher, err := fetch.Route(cfg.RepoURL)
	if err != nil {
		return 1, fmt.Errorf("routing: %w", err)
	}

	// Wire stdin reader for piped input
	if sf, ok := fetcher.(*fetch.StdinFetcher); ok {
		sf.Reader = os.Stdin
	}

	fetchOpts := fetch.FetchOptions{
		GithubToken: cfg.GithubToken,
		GitlabToken: cfg.GitlabToken,
		SubPath:     cfg.SubPath,
	}

	repo, err := fetcher.Fetch(ctx, cfg.RepoURL, fetchOpts)
	if err != nil {
		return 1, fmt.Errorf("fetching repo: %w", err)
	}

	// 13a. Update verification: --installed-sha
	if cfg.InstalledSHA != "" {
		archiveHash := engine.ComputeRepoHash(repo)
		if archiveHash == cfg.InstalledSHA {
			if err := emitter.Emit(engine.ResultEarlyEvent{
				Type:      "result",
				Verdict:   "PASS",
				Reasoning: "Installed SHA matches fetched repository content",
			}); err != nil {
				return 1, fmt.Errorf("writing output: %w", err)
			}
			return 0, nil
		}
		// SHA differs, proceed with full scan
	}

	// 7. Run scanners
	effectiveParanoiaLevel, _ := scan.ParseParanoia(effectiveParanoia)

	scanOpts := scan.Options{
		Paranoia:          effectiveParanoiaLevel,
		Format:            cfg.Format,
		LLMEndpoint:       cfg.LLMEndpoint,
		LLMKey:            cfg.LLMKey,
		LLMModel:          cfg.LLMModel,
		DBPath:            cfg.DBPath,
		InstalledSHA:      cfg.InstalledSHA,
		InstalledToolHash: cfg.InstalledToolHash,
		Force:             cfg.Force,
		Offline:           cfg.Offline,
		RepoPath:          cfg.SubPath,
		GithubToken:       cfg.GithubToken,
		GitlabToken:       cfg.GitlabToken,
		LLMTimeout:        cfg.LLMTimeout,
		Rules:             rs,
		ToolManifest:      cfg.ToolManifest,
		ToolBaseline:      cfg.ToolBaseline,
	}

	if err := emitter.Emit(engine.NewProgressEvent("scan", "Running security scanners...")); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write progress: %v\n", err)
	}

	scanners := engine.BuildScannerList(scanOpts)
	events := scan.RunAll(ctx, repo, scanOpts, scanners)

	// Collect findings before emitting (suppression must happen first).
	// Runtime errors are emitted directly and never enter verdict computation.
	var allFindings []scan.Finding
	for ev := range events {
		switch v := ev.(type) {
		case scan.Finding:
			allFindings = append(allFindings, v)
		case scan.RuntimeError:
			if err := emitter.Emit(v); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write runtime error: %v\n", err)
			}
		}
	}

	// 13b. Update verification: --installed-tool-hash
	if cfg.InstalledToolHash != "" {
		toolFindings := engine.CheckToolHash(repo, cfg.InstalledToolHash)
		allFindings = append(allFindings, toolFindings...)
	}

	// 7b. Apply .honeybadgerignore suppression before emitting.
	var suppressedCount int
	if raw, ok := repo.Files[".honeybadgerignore"]; ok {
		ignoreSet, parseErr := ignore.Parse(raw, ".honeybadgerignore")
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse .honeybadgerignore: %v\n", parseErr)
		} else {
			var suppressed []ignore.SuppressedFinding
			allFindings, suppressed = ignoreSet.Filter(allFindings)
			suppressedCount = len(suppressed)
		}
	}

	// Now emit the kept findings.
	for _, f := range allFindings {
		if err := emitter.Emit(f); err != nil {
			return 1, fmt.Errorf("writing output: %w", err)
		}
	}

	// 8. Emit health event
	if err := emitter.Emit(engine.HealthEvent{
		Type:                 "health",
		Stars:                repo.Health.Stars,
		Contributors:         repo.Health.Contributors,
		AgeDays:              repo.Health.AgeDays,
		LastCommitDays:       repo.Health.LastCommitDays,
		HasLicense:           repo.Health.HasLicense,
		HasSecurityMD:        repo.Health.HasSecurityMD,
		HasSignedCommits:     repo.Health.HasSignedCommits,
		RecentOwnerChange:    repo.Health.RecentOwnerChange,
		IssuesMentioningRisk: repo.Health.IssuesMentioningRisk,
	}); err != nil {
		return 1, fmt.Errorf("writing output: %w", err)
	}

	// 9. LLM verdict
	var llmVerdict *report.LLMVerdict
	llmUsed := false
	if paranoia >= scan.ParanoiaFamily && cfg.LLMEndpoint != "" {
		if err := emitter.Emit(engine.NewProgressEvent("llm", "Asking LLM for verdict...")); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write progress: %v\n", err)
		}

		llmCtx, llmCancel := context.WithTimeout(ctx, cfg.LLMTimeout)
		defer llmCancel()

		llmOpts := report.LLMOptions{
			Paranoia: string(paranoia),
			Platform: runtime.GOOS,
			Tier:     tier,
		}
		prompt := report.AssembleLLMPrompt(repo, allFindings, llmOpts)
		v, err := report.CallLLM(llmCtx, prompt, cfg.LLMEndpoint, cfg.LLMKey, cfg.LLMModel)
		if err != nil {
			msg := fmt.Sprintf("LLM call failed: %v", err)
			if llmCtx.Err() == context.DeadlineExceeded {
				msg = fmt.Sprintf("LLM timed out after %v — using static findings only", cfg.LLMTimeout)
			}
			if err := emitter.Emit(engine.NewProgressEvent("llm", msg)); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write progress: %v\n", err)
			}
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
	result := engine.ResultEvent{
		Type:              "result",
		Verdict:           verdict,
		Reasoning:         reasoning,
		KeyFinding:        keyFinding,
		FindingCounts:     findingCounts,
		CVECount:          cveCount,
		CVEMaxSeverity:    cveMaxSev,
		Attested:          false,
		LLMModel:          cfg.LLMModel,
		LLMUsed:           llmUsed,
		Paranoia:          string(paranoia),
		EffectiveParanoia: effectiveParanoia,
		Tier:              tier,
		Sandbox:           sandboxType,
		ScannedAt:         time.Now().UTC().Format(time.RFC3339),
		DurationMS:        time.Since(start).Milliseconds(),
	}
	if err := emitter.Emit(result); err != nil {
		return 1, fmt.Errorf("writing output: %w", err)
	}

	// Emit suppression summary if any findings were suppressed
	if suppressedCount > 0 {
		if err := emitter.Emit(engine.SuppressionEvent{
			Type:            "suppression_summary",
			SuppressedCount: suppressedCount,
		}); err != nil {
			return 1, fmt.Errorf("writing output: %w", err)
		}
	}

	// Write audit if --db provided
	if cfg.DBPath != "" {
		if err := store.WriteAudit(cfg.DBPath, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: audit write failed: %v\n", err)
		}
	}

	// 12. Exit code
	return engine.ExitCodeForVerdict(verdict), nil
}

func serveMCP(rulesDir string) error {
	s := newMCPServer(rulesDir)
	return server.ServeStdio(s)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
