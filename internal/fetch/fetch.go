package fetch

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Health holds repo health signals fed to the LLM as context.
type Health struct {
	Stars                int      `json:"stars"`
	Contributors         int      `json:"contributors"`
	AgeDays              int      `json:"age_days"`
	LastCommitDays       int      `json:"last_commit_days"`
	HasLicense           bool     `json:"has_license"`
	HasSecurityMD        bool     `json:"has_security_md"`
	HasSignedCommits     bool     `json:"has_signed_commits"`
	RecentOwnerChange    bool     `json:"recent_ownership_change"`
	IssuesMentioningRisk []string `json:"issues_mentioning_risk"`
}

// Repo holds all fetched data about a repository.
type Repo struct {
	URL       string            // original URL
	Owner     string            // e.g. "famclaw"
	Name      string            // e.g. "honeybadger"
	Platform  string            // "github", "gitlab", "local"
	SHA       string            // HEAD commit SHA
	Branch    string            // default branch
	Files     map[string][]byte // path -> content (all text files)
	Health    Health
	FetchedAt time.Time
}

// Fetcher retrieves repository data from a source.
type Fetcher interface {
	Fetch(ctx context.Context, url string, opts FetchOptions) (*Repo, error)
}

// FetchOptions controls fetch behavior.
type FetchOptions struct {
	GithubToken string
	GitlabToken string
	SubPath     string // subdirectory within repo (for monorepos)
}

// Route selects the appropriate Fetcher based on URL pattern.
func Route(url string) (Fetcher, error) {
	switch {
	case url == "-":
		return &StdinFetcher{}, nil
	case strings.Contains(url, "github.com"):
		return &GitHubFetcher{}, nil
	case strings.Contains(url, "gitlab.com"):
		return &GitLabFetcher{}, nil
	case strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://"):
		return &TarballFetcher{}, nil
	case url == "":
		return nil, fmt.Errorf("routing: empty URL")
	case !strings.Contains(url, "://"):
		// Assume local path
		return &LocalFetcher{}, nil
	default:
		return nil, fmt.Errorf("routing: unsupported URL: %s", url)
	}
}
