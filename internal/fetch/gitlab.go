package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GitLabFetcher fetches repository data via GitLab REST API v4.
type GitLabFetcher struct {
	// BaseURL overrides the GitLab API base URL. Defaults to "https://gitlab.com/api/v4".
	BaseURL string
}

func (g *GitLabFetcher) baseURL() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return "https://gitlab.com/api/v4"
}

// Fetch retrieves a GitLab repository's files and health signals.
func (g *GitLabFetcher) Fetch(ctx context.Context, rawURL string, opts FetchOptions) (*Repo, error) {
	projectPath, err := parseGitLabURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("gitlab: parsing URL: %w", err)
	}

	token := opts.GitlabToken
	encodedPath := url.PathEscape(projectPath)

	// 1. Project metadata
	projectData, err := g.fetchProjectMetadata(ctx, encodedPath, token)
	if err != nil {
		return nil, fmt.Errorf("gitlab: fetching project metadata: %w", err)
	}

	projectID := int(jsonFloat(projectData, "id"))
	defaultBranch := jsonString(projectData, "default_branch")
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	stars := int(jsonFloat(projectData, "star_count"))
	createdAt, _ := time.Parse(time.RFC3339, jsonString(projectData, "created_at"))
	lastActivity, _ := time.Parse(time.RFC3339, jsonString(projectData, "last_activity_at"))

	// Check for license via project data
	hasLicense := false
	if licenseData, ok := projectData["license"].(map[string]interface{}); ok && licenseData != nil {
		hasLicense = true
	}

	// Extract owner/name from project path
	parts := strings.SplitN(projectPath, "/", 2)
	owner := ""
	name := projectPath
	if len(parts) == 2 {
		owner = parts[0]
		name = parts[1]
	}

	// 2. Recursive file tree (paginated)
	treePaths, err := g.fetchTree(ctx, projectID, defaultBranch, token)
	if err != nil {
		return nil, fmt.Errorf("gitlab: fetching file tree: %w", err)
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
		content, err := g.fetchFileContent(ctx, projectID, path, defaultBranch, token)
		if err != nil {
			continue
		}
		files[path] = content
	}

	// 4. Health signals
	contributors := g.fetchContributorsCount(ctx, projectID, token)

	now := time.Now()
	ageDays := int(now.Sub(createdAt).Hours() / 24)
	lastCommitDays := int(now.Sub(lastActivity).Hours() / 24)

	repo := &Repo{
		URL:      rawURL,
		Owner:    owner,
		Name:     name,
		Platform: "gitlab",
		Branch:   defaultBranch,
		Files:    files,
		Health: Health{
			Stars:          stars,
			Contributors:   contributors,
			AgeDays:        ageDays,
			LastCommitDays: lastCommitDays,
			HasLicense:     hasLicense,
			HasSecurityMD:  hasSecurityMD,
		},
		FetchedAt: now,
	}

	return repo, nil
}

// fetchProjectMetadata retrieves project metadata from GET /projects/{encoded_path}.
func (g *GitLabFetcher) fetchProjectMetadata(ctx context.Context, encodedPath, token string) (map[string]interface{}, error) {
	apiPath := fmt.Sprintf("/projects/%s", encodedPath)
	body, _, err := g.gitlabAPI(ctx, apiPath, token)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decoding project metadata: %w", err)
	}
	return data, nil
}

// fetchTree retrieves the recursive file tree with pagination.
func (g *GitLabFetcher) fetchTree(ctx context.Context, projectID int, branch, token string) ([]string, error) {
	var allPaths []string
	page := 1

	for {
		apiPath := fmt.Sprintf("/projects/%d/repository/tree?recursive=true&per_page=100&page=%d&ref=%s", projectID, page, branch)
		body, headers, err := g.gitlabAPI(ctx, apiPath, token)
		if err != nil {
			return nil, err
		}

		var entries []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(body, &entries); err != nil {
			return nil, fmt.Errorf("decoding tree page %d: %w", page, err)
		}

		if len(entries) == 0 {
			break
		}

		for _, e := range entries {
			if e.Type == "blob" {
				allPaths = append(allPaths, e.Path)
			}
		}

		// Check for next page
		nextPage := headers.Get("X-Next-Page")
		if nextPage == "" || nextPage == "0" {
			break
		}
		page++
	}

	return allPaths, nil
}

// fetchFileContent retrieves a single file's raw content.
func (g *GitLabFetcher) fetchFileContent(ctx context.Context, projectID int, filePath, branch, token string) ([]byte, error) {
	encodedFilePath := url.PathEscape(filePath)
	apiPath := fmt.Sprintf("/projects/%d/repository/files/%s/raw?ref=%s", projectID, encodedFilePath, branch)
	body, _, err := g.gitlabAPI(ctx, apiPath, token)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// fetchContributorsCount returns the number of contributors for a project.
func (g *GitLabFetcher) fetchContributorsCount(ctx context.Context, projectID int, token string) int {
	apiPath := fmt.Sprintf("/projects/%d/repository/contributors", projectID)
	body, _, err := g.gitlabAPI(ctx, apiPath, token)
	if err != nil {
		return 0
	}
	var contributors []interface{}
	if err := json.Unmarshal(body, &contributors); err != nil {
		return 0
	}
	return len(contributors)
}

// gitlabAPI makes a GET request to the GitLab API with optional auth.
func (g *GitLabFetcher) gitlabAPI(ctx context.Context, path, token string) ([]byte, http.Header, error) {
	fullURL := g.baseURL() + path

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating request: %w", err)
		}
		if token != "" {
			req.Header.Set("PRIVATE-TOKEN", token)
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
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				seconds, _ := strconv.Atoi(retryAfter)
				if seconds > 0 {
					select {
					case <-ctx.Done():
						return nil, nil, ctx.Err()
					case <-time.After(time.Duration(seconds) * time.Second):
					}
					continue
				}
			}
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, nil, fmt.Errorf("API %s returned status %d: %s", path, resp.StatusCode, string(body))
		}

		return body, resp.Header, nil
	}

	return nil, nil, fmt.Errorf("API %s: max retries exceeded", path)
}

// parseGitLabURL extracts the project path from a GitLab URL.
func parseGitLabURL(rawURL string) (string, error) {
	u := rawURL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "gitlab.com/")
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimRight(u, "/")

	if u == "" || !strings.Contains(u, "/") {
		return "", fmt.Errorf("invalid GitLab URL %q: expected owner/repo", rawURL)
	}

	return u, nil
}
