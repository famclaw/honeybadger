package fetch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// httpClient is a shared HTTP client with a reasonable timeout.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// maxRateLimitWait is the maximum time to wait for rate limit reset before returning an error.
const maxRateLimitWait = 60 * time.Second

// defaultMaxFileBytes is the default maximum file size to fetch (1 MB).
const defaultMaxFileBytes = 1024 * 1024

// GitHubFetcher fetches repository data via GitHub REST API.
type GitHubFetcher struct {
	// BaseURL overrides the GitHub API base URL. Defaults to "https://api.github.com".
	BaseURL string
}

func (g *GitHubFetcher) baseURL() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return "https://api.github.com"
}

// Fetch retrieves a GitHub repository's files and health signals.
func (g *GitHubFetcher) Fetch(ctx context.Context, url string, opts FetchOptions) (*Repo, error) {
	owner, repoName, err := parseGitHubURL(url)
	if err != nil {
		return nil, fmt.Errorf("github: parsing URL: %w", err)
	}

	token := opts.GithubToken

	// 1. Repo metadata
	repoData, err := g.fetchRepoMetadata(ctx, owner, repoName, token)
	if err != nil {
		return nil, fmt.Errorf("github: fetching repo metadata: %w", err)
	}

	defaultBranch, _ := repoData["default_branch"].(string)
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	stars := int(jsonFloat(repoData, "stargazers_count"))
	hasLicense := repoData["license"] != nil && repoData["license"] != false
	createdAt, _ := time.Parse(time.RFC3339, jsonString(repoData, "created_at"))
	pushedAt, _ := time.Parse(time.RFC3339, jsonString(repoData, "pushed_at"))

	// Resolve the default-branch tip commit SHA so every tree/content fetch
	// pins to an immutable ref instead of a mutable branch. The /repos endpoint
	// does not expose a top-level sha, so resolve it from the branch tip.
	sha, _ := repoData["sha"].(string)
	if sha == "" {
		sha, _ = g.resolveCommitSHA(ctx, owner, repoName, defaultBranch, token)
	}
	// ref is what every tree/contents call targets: the commit SHA when it was
	// resolved, otherwise (as a fallback) the mutable branch ref.
	ref := defaultBranch
	if sha != "" {
		ref = sha
	}

	// 2. Recursive file tree
	repo := &Repo{
		URL:      url,
		Owner:    owner,
		Name:     repoName,
		Platform: "github",
		SHA:      sha,
		Branch:   defaultBranch,
		Files:    make(map[string][]byte),
	}
	if sha == "" {
		// Fallback means content was fetched against a mutable branch ref, which
		// can move between the tree listing and the content fetch. Flag it.
		repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
			Type:     "coverage-incomplete",
			Severity: "MEDIUM",
			Check:    "github-tree",
			Message:  fmt.Sprintf("Could not resolve the commit SHA for %s/%s branch %q; content fetched against the mutable branch ref", owner, repoName, defaultBranch),
		})
	}

	treePaths, err := g.fetchTree(ctx, owner, repoName, ref, token, repo)
	if err != nil {
		return nil, fmt.Errorf("github: fetching file tree: %w", err)
	}

	// 3. File contents
	hasSecurityMD := false
	maxBytes := maxFileBytes()

	// Enumerate the scannable candidates (non-binary, subpath-filtered) first so
	// we can cap the number of per-file downloads; a huge tree must not trigger
	// unbounded content API calls.
	candidates := make([]string, 0, len(treePaths))
	for _, path := range treePaths {
		if isBinaryExtension(path) {
			continue
		}
		if opts.SubPath != "" && !strings.HasPrefix(path, opts.SubPath) {
			continue
		}
		candidates = append(candidates, path)
	}
	maxFiles := maxFileCount()
	if len(candidates) > maxFiles {
		repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
			Type:     "coverage-incomplete",
			Severity: "HIGH",
			Check:    "github-tree",
			Message:  fmt.Sprintf("Repository has %d scannable files, exceeding the %d-file cap; only the first %d were fetched and scanned", len(candidates), maxFiles, maxFiles),
		})
		candidates = candidates[:maxFiles]
	}

	for _, path := range candidates {
		if strings.ToUpper(filepath.Base(path)) == "SECURITY.MD" {
			hasSecurityMD = true
		}
		content, err := g.fetchFileContent(ctx, owner, repoName, path, ref, token)
		if err != nil {
			// A file present in the tree but not fetchable means the scan is
			// coverage-incomplete. Report it rather than dropping it silently.
			if isOversizedErr(err, maxBytes) {
				repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
					Type:     "coverage-incomplete",
					Severity: "HIGH",
					Check:    "github-tree",
					File:     path,
					Message:  fmt.Sprintf("File %s exceeds %d-byte size cap and was not fetched", path, maxBytes),
				})
			} else {
				repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
					Type:     "coverage-incomplete",
					Severity: "MEDIUM",
					Check:    "github-file",
					File:     path,
					Message:  fmt.Sprintf("File %s is in the tree but could not be fetched and was not scanned: %v", path, err),
				})
			}
			continue
		}
		if len(content) > maxBytes {
			repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
				Type:     "coverage-incomplete",
				Severity: "HIGH",
				Check:    "github-tree",
				File:     path,
				Message:  fmt.Sprintf("File %s exceeds %d-byte size cap (%d bytes) and was not scanned", path, maxBytes, len(content)),
			})
			continue
		}
		repo.Files[path] = content
	}

	// 4. Health signals
	contributors := g.fetchContributorsCount(ctx, owner, repoName, token)
	riskIssues := g.fetchRiskIssues(ctx, owner, repoName, token)

	now := time.Now()
	ageDays := int(now.Sub(createdAt).Hours() / 24)
	lastCommitDays := int(now.Sub(pushedAt).Hours() / 24)

	repo.Health = Health{
		Stars:                stars,
		Contributors:         contributors,
		AgeDays:              ageDays,
		LastCommitDays:       lastCommitDays,
		HasLicense:           hasLicense,
		HasSecurityMD:        hasSecurityMD,
		IssuesMentioningRisk: riskIssues,
	}
	repo.FetchedAt = now

	return repo, nil
}

// fetchRepoMetadata retrieves repository metadata from GET /repos/{owner}/{repo}.
func (g *GitHubFetcher) fetchRepoMetadata(ctx context.Context, owner, repo, token string) (map[string]any, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	body, _, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decoding repo metadata: %w", err)
	}
	return data, nil
}

// resolveCommitSHA resolves the default-branch tip commit SHA via the
// /repos/{owner}/{repo}/commits/{branch} endpoint.
func (g *GitHubFetcher) resolveCommitSHA(ctx context.Context, owner, repo, branch, token string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, branch)
	body, _, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return "", fmt.Errorf("resolving commit SHA for %s/%s@%s: %w", owner, repo, branch, err)
	}
	var data struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("decoding commit SHA for %s/%s@%s: %w", owner, repo, branch, err)
	}
	if data.SHA == "" {
		return "", fmt.Errorf("resolving commit SHA for %s/%s@%s: empty sha in response", owner, repo, branch)
	}
	return data.SHA, nil
}

// fetchTree retrieves the recursive file tree for a ref (commit SHA or branch).
// Sets treeTruncated on the repo if the GitHub API truncated the tree response.
func (g *GitHubFetcher) fetchTree(ctx context.Context, owner, repoName, ref, token string, repo *Repo) ([]string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", owner, repoName, ref)
	body, _, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return nil, err
	}
	var data struct {
		Truncated bool `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decoding tree: %w", err)
	}
	if data.Truncated {
		repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
			Type:     "coverage-incomplete",
			Severity: "HIGH",
			Check:    "github-tree",
			Message:  fmt.Sprintf("GitHub tree API returned truncated: true — %s is too large to enumerate fully; some files were not scanned", repo.Name),
		})
	}
	var paths []string
	for _, entry := range data.Tree {
		if entry.Type == "blob" {
			paths = append(paths, entry.Path)
		}
	}
	return paths, nil
}

// fetchFileContent retrieves a single file's content via the contents API,
// pinned to the given ref (a commit SHA when resolved, else a branch).
func (g *GitHubFetcher) fetchFileContent(ctx context.Context, owner, repo, filePath, ref, token string) ([]byte, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", owner, repo, filePath, url.QueryEscape(ref))
	body, _, err := g.githubAPI(ctx, apiPath, token)
	if err != nil {
		return nil, err
	}
	var data struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decoding file content for %s: %w", filePath, err)
	}
	if data.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q for %s", data.Encoding, filePath)
	}
	// GitHub base64 content may contain newlines
	clean := strings.ReplaceAll(data.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding %s: %w", filePath, err)
	}
	return decoded, nil
}

// fetchContributorsCount returns the number of contributors for a repo.
// Uses per_page=1 and parses the Link header to get total count without fetching all pages.
func (g *GitHubFetcher) fetchContributorsCount(ctx context.Context, owner, repo, token string) int {
	path := fmt.Sprintf("/repos/%s/%s/contributors?per_page=1&anon=true", owner, repo)
	_, headers, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return 0
	}
	// Parse Link header for last page number: <...?page=42>; rel="last"
	link := headers.Get("Link")
	if link == "" {
		return 1 // only one page means 1 contributor
	}
	for _, part := range strings.Split(link, ",") {
		if strings.Contains(part, `rel="last"`) {
			// Extract page number from <...?page=N>
			start := strings.Index(part, "page=")
			if start < 0 {
				continue
			}
			numStr := part[start+5:]
			end := strings.IndexAny(numStr, ">&")
			if end > 0 {
				numStr = numStr[:end]
			}
			n, err := strconv.Atoi(numStr)
			if err == nil {
				return n
			}
		}
	}
	return 1
}

// fetchRiskIssues searches issues for security-related keywords.
func (g *GitHubFetcher) fetchRiskIssues(ctx context.Context, owner, repo, token string) []string {
	path := fmt.Sprintf("/search/issues?q=repo:%s/%s+malware+OR+backdoor+OR+compromised+OR+hijacked", owner, repo)
	body, _, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return nil
	}
	var data struct {
		Items []struct {
			Title string `json:"title"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	var titles []string
	for _, item := range data.Items {
		titles = append(titles, item.Title)
	}
	return titles
}

// githubAPI makes a GET request to the GitHub API with optional auth.
func (g *GitHubFetcher) githubAPI(ctx context.Context, path, token string) ([]byte, http.Header, error) {
	fullURL := g.baseURL() + path

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("executing request to %s: %w", path, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading response from %s: %w", path, err)
		}

		// Handle rate limiting
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			remaining := resp.Header.Get("X-RateLimit-Remaining")
			if remaining == "0" || resp.StatusCode == http.StatusTooManyRequests {
				resetStr := resp.Header.Get("X-RateLimit-Reset")
				if resetStr != "" {
					resetUnix, _ := strconv.ParseInt(resetStr, 10, 64)
					resetTime := time.Unix(resetUnix, 0)
					waitDur := time.Until(resetTime)
					if waitDur > maxRateLimitWait {
						return nil, nil, fmt.Errorf("API %s: rate limit reset in %v exceeds max wait of %v", path, waitDur, maxRateLimitWait)
					}
					if waitDur > 0 {
						select {
						case <-ctx.Done():
							return nil, nil, ctx.Err()
						case <-time.After(waitDur):
						}
						continue
					}
				}
				// Exponential backoff if no reset header
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(backoff):
				}
				continue
			}
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, nil, fmt.Errorf("API %s returned status %d: %s", path, resp.StatusCode, string(body))
		}

		return body, resp.Header, nil
	}

	return nil, nil, fmt.Errorf("API %s: max retries exceeded", path)
}

// parseGitHubURL extracts owner and repo from a GitHub URL.
func parseGitHubURL(url string) (owner, repo string, err error) {
	// Handle SSH format: git@github.com:owner/repo.git
	if strings.HasPrefix(url, "git@") {
		// Remove the git@ prefix
		u := strings.TrimPrefix(url, "git@")
		// Split on : to separate host from path
		parts := strings.SplitN(u, ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid GitHub SSH URL %q: expected git@github.com:owner/repo", url)
		}
		// Remove the host part (github.com) and trailing .git
		u = strings.TrimPrefix(parts[1], "github.com/")
		u = strings.TrimSuffix(u, ".git")
		// Remove trailing slash
		u = strings.TrimRight(u, "/")

		parts = strings.SplitN(u, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid GitHub SSH URL %q: expected owner/repo", url)
		}
		return parts[0], parts[1], nil
	}

	// Remove scheme
	u := url
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	// Remove github.com prefix
	u = strings.TrimPrefix(u, "github.com/")
	// Remove trailing .git
	u = strings.TrimSuffix(u, ".git")
	// Remove trailing slash
	u = strings.TrimRight(u, "/")

	parts := strings.SplitN(u, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid GitHub URL %q: expected owner/repo", url)
	}
	return parts[0], parts[1], nil
}

// isBinaryExtension returns true if the file extension suggests a binary file.
func isBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz",
		".wasm", ".bin", ".exe", ".dll", ".so", ".dylib", ".ico", ".svg",
		".bmp", ".tiff", ".webp", ".mp3", ".mp4", ".avi", ".mov":
		return true
	}
	return false
}

// jsonFloat extracts a float64 from a map.
func jsonFloat(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	f, _ := v.(float64)
	return f
}

// jsonString extracts a string from a map.
func jsonString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// maxFileBytes returns the configured maximum file size in bytes.
// Read from HONEYBADGER_MAX_FILE_BYTES env var; falls back to defaultMaxFileBytes (1 MB).
func maxFileBytes() int {
	if s := os.Getenv("HONEYBADGER_MAX_FILE_BYTES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxFileBytes
}

// isOversizedErr reports whether the error indicates a file that exceeds the size cap.
// GitHub returns 403 for blobs larger than the configured max, but also returns
// 403 for rate-limiting and other non-size issues. We match only on messages
// that explicitly reference size limits to avoid false positives.
func isOversizedErr(err error, maxBytes int) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// GitHub contents API returns 403 for files exceeding size limits.
	// Only match size-specific messages, not generic 403s (rate limiting, etc.).
	if strings.Contains(msg, "size limit") || strings.Contains(msg, "too large") {
		return true
	}
	// GitHub API also returns 403 with a message like "resource protected by organization ...".
	// Check the response body for size-limit context when available.
	return false
}
