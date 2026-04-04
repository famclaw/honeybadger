package fetch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// httpClient is a shared HTTP client with a reasonable timeout.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// maxRateLimitWait is the maximum time to wait for rate limit reset before returning an error.
const maxRateLimitWait = 60 * time.Second

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
	sha, _ := repoData["sha"].(string) // may not be in repo endpoint

	// 2. Recursive file tree
	treePaths, err := g.fetchTree(ctx, owner, repoName, defaultBranch, token)
	if err != nil {
		return nil, fmt.Errorf("github: fetching file tree: %w", err)
	}

	// 3. File contents
	files := make(map[string][]byte)
	hasSecurityMD := false
	for _, path := range treePaths {
		if isBinaryExtension(path) {
			continue
		}
		if opts.SubPath != "" && !strings.HasPrefix(path, opts.SubPath) {
			continue
		}
		if strings.ToUpper(filepath.Base(path)) == "SECURITY.MD" {
			hasSecurityMD = true
		}
		content, err := g.fetchFileContent(ctx, owner, repoName, path, token)
		if err != nil {
			// Skip files that fail to fetch (e.g., too large)
			continue
		}
		files[path] = content
	}

	// 4. Health signals
	contributors := g.fetchContributorsCount(ctx, owner, repoName, token)
	riskIssues := g.fetchRiskIssues(ctx, owner, repoName, token)

	now := time.Now()
	ageDays := int(now.Sub(createdAt).Hours() / 24)
	lastCommitDays := int(now.Sub(pushedAt).Hours() / 24)

	repo := &Repo{
		URL:      url,
		Owner:    owner,
		Name:     repoName,
		Platform: "github",
		SHA:      sha,
		Branch:   defaultBranch,
		Files:    files,
		Health: Health{
			Stars:                stars,
			Contributors:         contributors,
			AgeDays:              ageDays,
			LastCommitDays:       lastCommitDays,
			HasLicense:           hasLicense,
			HasSecurityMD:        hasSecurityMD,
			IssuesMentioningRisk: riskIssues,
		},
		FetchedAt: now,
	}

	return repo, nil
}

// fetchRepoMetadata retrieves repository metadata from GET /repos/{owner}/{repo}.
func (g *GitHubFetcher) fetchRepoMetadata(ctx context.Context, owner, repo, token string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)
	body, _, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decoding repo metadata: %w", err)
	}
	return data, nil
}

// fetchTree retrieves the recursive file tree for a branch.
func (g *GitHubFetcher) fetchTree(ctx context.Context, owner, repo, branch, token string) ([]string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, branch)
	body, _, err := g.githubAPI(ctx, path, token)
	if err != nil {
		return nil, err
	}
	var data struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decoding tree: %w", err)
	}
	var paths []string
	for _, entry := range data.Tree {
		if entry.Type == "blob" {
			paths = append(paths, entry.Path)
		}
	}
	return paths, nil
}

// fetchFileContent retrieves a single file's content via the contents API.
func (g *GitHubFetcher) fetchFileContent(ctx context.Context, owner, repo, filePath, token string) ([]byte, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, filePath)
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
func jsonFloat(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	f, _ := v.(float64)
	return f
}

// jsonString extracts a string from a map.
func jsonString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
