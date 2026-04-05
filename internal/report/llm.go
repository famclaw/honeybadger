package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// LLMOptions configures the LLM prompt assembly.
type LLMOptions struct {
	Paranoia     string
	Platform     string
	Tier         string
	ToolsRan     []string
	ToolsSkipped []struct{ Name, Reason string }
}

// LLMVerdict is the parsed response from the LLM.
type LLMVerdict struct {
	Verdict    string `json:"verdict"`     // PASS, WARN, FAIL
	Reasoning  string `json:"reasoning"`
	KeyFinding string `json:"key_finding"` // or null
}

const maxTokenBudget = 32000
const charsPerToken = 4
const maxCharBudget = maxTokenBudget * charsPerToken

const promptTemplate = `You are HoneyBadger, a security scanner for software plugins about to be
installed on a family home server running AI assistants. Children use this server.

Analyze the data below and give a security verdict.

Verdict must be exactly one of: PASS | WARN | FAIL

Rules:
- Be specific. Quote file and line number for every finding you mention.
- Do not fail on theoretical issues. Require concrete evidence.
- A WARN for an undeclared network call is appropriate. A FAIL requires something worse.
- Consider the context: a family home server, children present, local network.
- If paranoia=strict or paranoid and no attestation found, that alone is WARN.

Paranoia level: %s
Platform: %s
Tier: %s

Tools ran: %s
Tools skipped: %s

--- REPO ---
URL: %s
SHA: %s
Stars: %d | Contributors: %d | Age: %d days | Last commit: %d days ago
License: %v | Security.md: %v | Signed commits: %v | Recent owner change: %v

--- FINDINGS (JSON) ---
%s

--- SOURCE FILES ---
%s

Respond with JSON only:
{"verdict":"PASS|WARN|FAIL","reasoning":"...","key_finding":"...or null"}
`

// AssembleLLMPrompt builds the security analysis prompt for the LLM.
// Budget: 32,000 tokens max (safe for free tier models and small local models).
func AssembleLLMPrompt(repo *fetch.Repo, findings []scan.Finding, opts LLMOptions) string {
	// Format tools ran / skipped
	toolsRan := "none"
	if len(opts.ToolsRan) > 0 {
		toolsRan = strings.Join(opts.ToolsRan, ", ")
	}
	toolsSkipped := "none"
	if len(opts.ToolsSkipped) > 0 {
		parts := make([]string, len(opts.ToolsSkipped))
		for i, t := range opts.ToolsSkipped {
			parts[i] = fmt.Sprintf("%s (%s)", t.Name, t.Reason)
		}
		toolsSkipped = strings.Join(parts, ", ")
	}

	// Marshal findings
	findingsJSON, err := json.Marshal(findings)
	if err != nil {
		findingsJSON = []byte("[]")
	}

	// Build the header (everything except source files)
	header := fmt.Sprintf(promptTemplate,
		opts.Paranoia,
		opts.Platform,
		opts.Tier,
		toolsRan,
		toolsSkipped,
		repo.URL,
		repo.SHA,
		repo.Health.Stars,
		repo.Health.Contributors,
		repo.Health.AgeDays,
		repo.Health.LastCommitDays,
		repo.Health.HasLicense,
		repo.Health.HasSecurityMD,
		repo.Health.HasSignedCommits,
		repo.Health.RecentOwnerChange,
		string(findingsJSON),
		"%s", // placeholder for source files
	)

	headerLen := len(header) - 2 // subtract the %s placeholder
	remaining := maxCharBudget - headerLen

	// Prioritize files for inclusion
	sourceBlock := buildSourceBlock(repo, findings, remaining)

	return fmt.Sprintf(header, sourceBlock)
}

// filePriority returns a priority rank (lower = higher priority).
func filePriority(path string, findingFiles map[string]bool) int {
	lower := strings.ToLower(path)

	// Priority 1: dependency files
	depFiles := []string{"go.mod", "go.sum", "package.json", "package-lock.json",
		"requirements.txt", "pyproject.toml", "cargo.toml", "cargo.lock",
		"gemfile", "gemfile.lock", "pom.xml", "build.gradle"}
	for _, d := range depFiles {
		if strings.HasSuffix(lower, d) {
			return 1
		}
	}

	// Priority 2: install/build scripts
	buildFiles := []string{"install.sh", "makefile", "setup.py", "setup.cfg",
		"dockerfile", "docker-compose.yml", "justfile", "taskfile.yml"}
	for _, b := range buildFiles {
		if strings.HasSuffix(lower, b) {
			return 2
		}
	}

	// Priority 3: files containing findings
	if findingFiles[path] {
		return 3
	}

	// Priority 4: main entry points
	entryFiles := []string{"main.go", "index.js", "index.ts", "__init__.py",
		"app.go", "app.js", "app.py", "cmd/main.go"}
	for _, e := range entryFiles {
		if strings.HasSuffix(lower, e) {
			return 4
		}
	}

	// Priority 5: other source files
	return 5
}

func buildSourceBlock(repo *fetch.Repo, findings []scan.Finding, budget int) string {
	// Build set of files referenced in findings
	findingFiles := make(map[string]bool)
	for _, f := range findings {
		if f.File != "" {
			findingFiles[f.File] = true
		}
	}

	// Sort files by priority
	type fileEntry struct {
		path     string
		priority int
	}
	entries := make([]fileEntry, 0, len(repo.Files))
	for path := range repo.Files {
		entries = append(entries, fileEntry{path: path, priority: filePriority(path, findingFiles)})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority != entries[j].priority {
			return entries[i].priority < entries[j].priority
		}
		return entries[i].path < entries[j].path
	})

	var buf strings.Builder
	used := 0
	for _, e := range entries {
		content := repo.Files[e.path]
		block := fmt.Sprintf("=== %s ===\n%s\n", e.path, string(content))
		if used+len(block) > budget {
			// Try to include at least the filename
			if used+len(e.path)+20 < budget {
				buf.WriteString(fmt.Sprintf("=== %s === (truncated)\n", e.path))
			}
			break
		}
		buf.WriteString(block)
		used += len(block)
	}
	return buf.String()
}

// CallLLM sends the prompt to the configured LLM endpoint and parses the verdict.
func CallLLM(ctx context.Context, prompt string, endpoint, apiKey, model string) (*LLMVerdict, error) {
	if endpoint == "" {
		return nil, nil
	}

	// Build request body
	reqBody := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature":     0.1,
		"response_format": map[string]string{"type": "json_object"},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("llm request marshal: %w", err)
	}

	url := strings.TrimRight(endpoint, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("llm request create: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	llmClient := &http.Client{Timeout: 120 * time.Second}
	resp, err := llmClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm request send: %w", err)
	}
	defer resp.Body.Close()

	// Limit response to 1MB to prevent memory exhaustion from rogue endpoints
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("llm response read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm response status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse OpenAI-compatible response
	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("llm response unmarshal: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("llm response: no choices returned")
	}

	content := chatResp.Choices[0].Message.Content
	var verdict LLMVerdict
	if err := json.Unmarshal([]byte(content), &verdict); err != nil {
		return nil, fmt.Errorf("llm verdict parse: %w", err)
	}

	return &verdict, nil
}
