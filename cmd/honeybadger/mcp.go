package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/report"
	"github.com/famclaw/honeybadger/internal/scan"
)

// newMCPServer creates and configures the HoneyBadger MCP server with its tools.
func newMCPServer() *server.MCPServer {
	s := server.NewMCPServer("honeybadger", Version,
		server.WithToolCapabilities(true),
	)

	tool := mcp.NewTool("honeybadger_scan",
		mcp.WithDescription("Scan a GitHub or GitLab repository for security issues before installation. Returns PASS/WARN/FAIL with detailed reasoning."),
		mcp.WithString("repo_url",
			mcp.Required(),
			mcp.Description("GitHub or GitLab repository URL"),
		),
		mcp.WithString("paranoia",
			mcp.Description("Paranoia level for scanning"),
			mcp.Enum("minimal", "family", "strict", "paranoid"),
		),
		mcp.WithString("installed_sha",
			mcp.Description("SHA256 of currently installed version archive"),
		),
		mcp.WithString("installed_tool_hash",
			mcp.Description("SHA256 of installed MCP tool definitions"),
		),
		mcp.WithString("path",
			mcp.Description("Subdirectory within repo to scan"),
		),
	)

	s.AddTool(tool, handleScan)
	return s
}

// handleScan implements the honeybadger_scan MCP tool handler.
// It runs the same fetch -> scan -> report pipeline as the CLI.
func handleScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	repoURL := req.GetString("repo_url", "")
	if repoURL == "" {
		return mcp.NewToolResultError("repo_url is required"), nil
	}

	paranoiaStr := req.GetString("paranoia", "family")
	installedSHA := req.GetString("installed_sha", "")
	installedToolHash := req.GetString("installed_tool_hash", "")
	subPath := req.GetString("path", "")

	githubToken := os.Getenv("GITHUB_TOKEN")
	gitlabToken := os.Getenv("GITLAB_TOKEN")
	llmEndpoint := os.Getenv("HONEYBADGER_LLM")
	llmKey := os.Getenv("HONEYBADGER_LLM_KEY")
	llmModel := os.Getenv("HONEYBADGER_LLM_MODEL")

	result, err := runScan(ctx, repoURL, paranoiaStr, installedSHA, installedToolHash, subPath, githubToken, gitlabToken, llmEndpoint, llmKey, llmModel)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshaling result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resultJSON)), nil
}

// runScan executes the full scan pipeline and returns the result map.
func runScan(ctx context.Context, repoURL, paranoiaStr, installedSHA, installedToolHash, subPath, githubToken, gitlabToken, llmEndpoint, llmKey, llmModel string) (map[string]any, error) {
	start := time.Now()

	// 1. Parse paranoia level
	paranoia, err := scan.ParseParanoia(paranoiaStr)
	if err != nil {
		return nil, fmt.Errorf("invalid paranoia: %w", err)
	}

	// 2. Fetch repo
	fetcher, err := fetch.Route(repoURL)
	if err != nil {
		return nil, fmt.Errorf("routing: %w", err)
	}

	fetchOpts := fetch.FetchOptions{
		GithubToken: githubToken,
		GitlabToken: gitlabToken,
		SubPath:     subPath,
	}

	repo, err := fetcher.Fetch(ctx, repoURL, fetchOpts)
	if err != nil {
		return nil, fmt.Errorf("fetching repo: %w", err)
	}

	// 3. Update verification: installed SHA
	if installedSHA != "" {
		archiveHash := computeRepoHash(repo)
		if archiveHash == installedSHA {
			return map[string]any{
				"type":      "result",
				"verdict":   "PASS",
				"reasoning": "Installed SHA matches fetched repository content",
			}, nil
		}
	}

	// 4. Run scanners
	effectiveParanoia := string(paranoia)
	if isTermux() {
		if scan.SeverityRank(string(paranoia)) > scan.SeverityRank(string(scan.ParanoiaFamily)) {
			effectiveParanoia = string(scan.ParanoiaFamily)
		}
	}
	effectiveParanoiaLevel, _ := scan.ParseParanoia(effectiveParanoia)

	scanOpts := scan.Options{
		Paranoia:          effectiveParanoiaLevel,
		Format:            "ndjson",
		LLMEndpoint:       llmEndpoint,
		LLMKey:            llmKey,
		LLMModel:          llmModel,
		InstalledSHA:      installedSHA,
		InstalledToolHash: installedToolHash,
		RepoPath:          subPath,
		GithubToken:       githubToken,
		GitlabToken:       gitlabToken,
	}

	findings := scan.RunAll(ctx, repo, scanOpts)
	var allFindings []scan.Finding
	for f := range findings {
		allFindings = append(allFindings, f)
	}

	// 5. Tool hash verification
	if installedToolHash != "" {
		toolFindings := checkToolHash(repo, installedToolHash)
		allFindings = append(allFindings, toolFindings...)
	}

	// 6. LLM verdict
	var llmVerdict *report.LLMVerdict
	llmUsed := false
	if paranoia >= scan.ParanoiaFamily && llmEndpoint != "" {
		llmOpts := report.LLMOptions{
			Paranoia: string(paranoia),
			Platform: runtime.GOOS,
			Tier:     "online",
		}
		prompt := report.AssembleLLMPrompt(repo, allFindings, llmOpts)
		v, err := report.CallLLM(ctx, prompt, llmEndpoint, llmKey, llmModel)
		if err == nil && v != nil {
			llmVerdict = v
			llmUsed = true
		}
	}

	// 7. Compute final verdict
	verdict, reasoning, keyFinding := computeVerdict(allFindings, paranoia, llmVerdict)

	// 8. Count findings by severity
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

	// 9. Build result
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
		"scanned_at":         time.Now().UTC().Format(time.RFC3339),
		"duration_ms":        time.Since(start).Milliseconds(),
	}

	return result, nil
}
