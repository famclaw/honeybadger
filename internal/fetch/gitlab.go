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

	// Resolve the default-branch tip commit SHA so every tree/content fetch
	// pins to an immutable ref instead of a mutable branch.
	sha, _ := g.resolveCommitSHA(ctx, projectID, defaultBranch, token)
	// ref is what every tree/content call targets: the commit SHA when it was
	// resolved, otherwise (as a fallback) the mutable branch ref.
	ref := defaultBranch
	if sha != "" {
		ref = sha
	}

	// Build the repo early so fetch-time coverage findings attach to it.
	repo := &Repo{
		URL:      rawURL,
		Owner:    owner,
		Name:     name,
		Platform: "gitlab",
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
			Check:    "gitlab-tree",
			Message:  fmt.Sprintf("Could not resolve the commit SHA for %s branch %q; content fetched against the mutable branch ref", name, defaultBranch),
		})
	}

	// 2. Recursive file tree (paginated)
	treePaths, err := g.fetchTree(ctx, projectID, ref, token)
	if err != nil {
		return nil, fmt.Errorf("gitlab: fetching file tree: %w", err)
	}

	// 3. File contents
	hasSecurityMD := false
	maxBytes := maxFileBytes()

	// Enumerate the scannable candidates first so we can cap the number of
	// per-file downloads; a huge tree must not trigger unbounded API calls.
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
			Check:    "gitlab-tree",
			Message:  fmt.Sprintf("Repository has %d scannable files, exceeding the %d-file cap; only the first %d were fetched and scanned", len(candidates), maxFiles, maxFiles),
		})
		candidates = candidates[:maxFiles]
	}

	for _, path := range candidates {
		if strings.ToUpper(filepath.Base(path)) == "SECURITY.MD" {
			hasSecurityMD = true
		}
		content, err := g.fetchFileContent(ctx, projectID, path, ref, token)
		if err != nil {
			// A file present in the tree but not fetchable means the scan is
			// coverage-incomplete. Report it rather than dropping it silently.
			repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
				Type:     "coverage-incomplete",
				Severity: "MEDIUM",
				Check:    "gitlab-file",
				File:     path,
				Message:  fmt.Sprintf("File %s is in the tree but could not be fetched and was not scanned: %v", path, err),
			})
			continue
		}
		if len(content) > maxBytes {
			repo.CoverageWarnings = append(repo.CoverageWarnings, CoverageWarning{
				Type:     "coverage-incomplete",
				Severity: "HIGH",
				Check:    "gitlab-tree",
				File:     path,
				Message:  fmt.Sprintf("File %s exceeds %d-byte size cap (%d bytes) and was not scanned", path, maxBytes, len(content)),
			})
			continue
		}
		repo.Files[path] = content
	}

	// 4. Health signals
	contributors := g.fetchContributorsCount(ctx, projectID, token)

	now := time.Now()
	ageDays := int(now.Sub(createdAt).Hours() / 24)
	lastCommitDays := int(now.Sub(lastActivity).Hours() / 24)

	repo.Health = Health{
		Stars:          stars,
		Contributors:   contributors,
		AgeDays:        ageDays,
		LastCommitDays: lastCommitDays,
		HasLicense:     hasLicense,
		HasSecurityMD:  hasSecurityMD,
	}
	repo.FetchedAt = now

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

// resolveCommitSHA resolves the default-branch tip commit SHA via the
// /projects/{id}/repository/commits?ref_name={branch} endpoint.
func (g *GitLabFetcher) resolveCommitSHA(ctx context.Context, projectID int, branch, token string) (string, error) {
	apiPath := fmt.Sprintf("/projects/%d/repository/commits?ref_name=%s&per_page=1", projectID, url.QueryEscape(branch))
	body, _, err := g.gitlabAPI(ctx, apiPath, token)
	if err != nil {
		return "", fmt.Errorf("resolving commit SHA for project %d branch %s: %w", projectID, branch, err)
	}
	var data []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("decoding commit list for project %d branch %s: %w", projectID, branch, err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("resolving commit SHA for project %d branch %s: no commits returned", projectID, branch)
	}
	return data[0].ID, nil
}

// fetchTree retrieves the recursive file tree for a ref (commit SHA or branch) with pagination.
func (g *GitLabFetcher) fetchTree(ctx context.Context, projectID int, ref, token string) ([]string, error) {
	var allPaths []string
	page := 1

	for {
		apiPath := fmt.Sprintf("/projects/%d/repository/tree?recursive=true&per_page=100&page=%d&ref=%s", projectID, page, url.QueryEscape(ref))
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

// fetchFileContent retrieves a single file's raw content, pinned to the given
// ref (a commit SHA when resolved, else a branch).
func (g *GitLabFetcher) fetchFileContent(ctx context.Context, projectID int, filePath, ref, token string) ([]byte, error) {
	encodedFilePath := url.PathEscape(filePath)
	apiPath := fmt.Sprintf("/projects/%d/repository/files/%s/raw?ref=%s", projectID, encodedFilePath, url.QueryEscape(ref))
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
	// Handle SSH format: git@gitlab.com:owner/repo.git
	if strings.HasPrefix(rawURL, "git@") {
		// Remove the git@ prefix
		u := strings.TrimPrefix(rawURL, "git@")
		// Split on : to separate host from path
		parts := strings.SplitN(u, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid GitLab SSH URL %q: expected git@gitlab.com:owner/repo", rawURL)
		}
		// Remove the host part (gitlab.com) and trailing .git
		u = strings.TrimPrefix(parts[1], "gitlab.com/")
		u = strings.TrimSuffix(u, ".git")
		// Remove trailing slash
		u = strings.TrimRight(u, "/")

		if u == "" || !strings.Contains(u, "/") {
			return "", fmt.Errorf("invalid GitLab SSH URL %q: expected owner/repo", rawURL)
		}

		return u, nil
	}

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
