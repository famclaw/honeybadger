package fetch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRoute(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantTyp string
		wantErr bool
	}{
		{"stdin", "-", "*fetch.StdinFetcher", false},
		{"github https", "https://github.com/owner/repo", "*fetch.GitHubFetcher", false},
		{"github bare", "github.com/owner/repo", "*fetch.GitHubFetcher", false},
		{"gitlab https", "https://gitlab.com/owner/repo", "*fetch.GitLabFetcher", false},
		{"gitlab bare", "gitlab.com/owner/repo", "*fetch.GitLabFetcher", false},
		{"tarball", "https://example.com/archive.tar.gz", "*fetch.TarballFetcher", false},
		{"http url", "http://example.com/archive.zip", "*fetch.TarballFetcher", false},
		{"local path", "/local/path", "*fetch.LocalFetcher", false},
		{"local relative", "some/local/path", "*fetch.LocalFetcher", false},
		{"empty string", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Route(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := fmt.Sprintf("%T", f)
			if got != tt.wantTyp {
				t.Errorf("Route(%q) = %s, want %s", tt.url, got, tt.wantTyp)
			}
		})
	}
}

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{"https", "https://github.com/famclaw/honeybadger", "famclaw", "honeybadger", false},
		{"https with .git", "https://github.com/famclaw/honeybadger.git", "famclaw", "honeybadger", false},
		{"bare", "github.com/famclaw/honeybadger", "famclaw", "honeybadger", false},
		{"http", "http://github.com/owner/repo", "owner", "repo", false},
		{"trailing slash", "https://github.com/owner/repo/", "owner", "repo", false},
		{"with subpath", "https://github.com/owner/repo/tree/main/src", "owner", "repo", false},
		{"missing repo", "https://github.com/owner", "", "", true},
		{"empty after prefix", "github.com/", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitHubURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

func TestParseGitLabURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{"https", "https://gitlab.com/owner/repo", "owner/repo", false},
		{"bare", "gitlab.com/owner/repo", "owner/repo", false},
		{"with .git", "https://gitlab.com/owner/repo.git", "owner/repo", false},
		{"nested group", "https://gitlab.com/org/group/repo", "org/group/repo", false},
		{"missing repo", "gitlab.com/owner", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGitLabURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseGitLabURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestGitHubFetcherWithMock(t *testing.T) {
	fileContent := "package main\n\nfunc main() {}\n"
	b64Content := base64.StdEncoding.EncodeToString([]byte(fileContent))

	mux := http.NewServeMux()

	// Repo metadata
	mux.HandleFunc("/repos/test-owner/test-repo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"stargazers_count": 42,
			"default_branch":   "main",
			"created_at":       time.Now().AddDate(0, -6, 0).Format(time.RFC3339),
			"pushed_at":        time.Now().AddDate(0, 0, -3).Format(time.RFC3339),
			"license":          map[string]string{"spdx_id": "MIT"},
		})
	})

	// File tree
	mux.HandleFunc("/repos/test-owner/test-repo/git/trees/main", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tree": []map[string]string{
				{"path": "main.go", "type": "blob"},
				{"path": "go.mod", "type": "blob"},
				{"path": "SECURITY.md", "type": "blob"},
				{"path": "image.png", "type": "blob"},
			},
		})
	})

	// File contents
	mux.HandleFunc("/repos/test-owner/test-repo/contents/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"content":  b64Content,
			"encoding": "base64",
		})
	})

	// Contributors
	mux.HandleFunc("/repos/test-owner/test-repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"login": "contributor1"},
		})
	})

	// Issue search
	mux.HandleFunc("/search/issues", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []map[string]interface{}{
				{"title": "Potential backdoor in dependency"},
			},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	fetcher := &GitHubFetcher{BaseURL: server.URL}
	ctx := context.Background()

	repo, err := fetcher.Fetch(ctx, "https://github.com/test-owner/test-repo", FetchOptions{})
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if repo.Owner != "test-owner" {
		t.Errorf("Owner = %q, want %q", repo.Owner, "test-owner")
	}
	if repo.Name != "test-repo" {
		t.Errorf("Name = %q, want %q", repo.Name, "test-repo")
	}
	if repo.Platform != "github" {
		t.Errorf("Platform = %q, want %q", repo.Platform, "github")
	}
	if repo.Branch != "main" {
		t.Errorf("Branch = %q, want %q", repo.Branch, "main")
	}
	if repo.Health.Stars != 42 {
		t.Errorf("Stars = %d, want %d", repo.Health.Stars, 42)
	}
	if !repo.Health.HasLicense {
		t.Error("HasLicense = false, want true")
	}
	if !repo.Health.HasSecurityMD {
		t.Error("HasSecurityMD = false, want true")
	}

	// Should have 3 text files (main.go, go.mod, SECURITY.md) but not image.png
	if len(repo.Files) != 3 {
		t.Errorf("len(Files) = %d, want 3 (got keys: %v)", len(repo.Files), fileKeys(repo.Files))
	}
	if _, ok := repo.Files["main.go"]; !ok {
		t.Error("Files missing main.go")
	}
	if string(repo.Files["main.go"]) != fileContent {
		t.Errorf("main.go content = %q, want %q", string(repo.Files["main.go"]), fileContent)
	}

	if repo.Health.Contributors != 1 {
		t.Errorf("Contributors = %d, want 1", repo.Health.Contributors)
	}
	if len(repo.Health.IssuesMentioningRisk) != 1 {
		t.Errorf("IssuesMentioningRisk count = %d, want 1", len(repo.Health.IssuesMentioningRisk))
	}
}

func TestGitHubFetcherAuth(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// Return minimal valid responses
		if strings.HasPrefix(r.URL.Path, "/repos/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/") && !strings.Contains(r.URL.Path, "/contributors") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"default_branch": "main",
				"created_at":     time.Now().Format(time.RFC3339),
				"pushed_at":      time.Now().Format(time.RFC3339),
			})
		} else if strings.Contains(r.URL.Path, "/git/trees/") {
			json.NewEncoder(w).Encode(map[string]interface{}{"tree": []interface{}{}})
		} else if strings.Contains(r.URL.Path, "/contributors") {
			json.NewEncoder(w).Encode([]interface{}{})
		} else if strings.HasPrefix(r.URL.Path, "/search/") {
			json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}})
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	fetcher := &GitHubFetcher{BaseURL: server.URL}
	ctx := context.Background()

	_, err := fetcher.Fetch(ctx, "https://github.com/owner/repo", FetchOptions{GithubToken: "test-token-123"})
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if gotAuth != "Bearer test-token-123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-token-123")
	}
}

func TestLocalFetcher(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "internal"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "internal", "lib.go"), []byte("package internal\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create a binary file (with null bytes)
	if err := os.WriteFile(filepath.Join(tmpDir, "binary.dat"), []byte{0x00, 0x01, 0x02}, 0644); err != nil {
		t.Fatal(err)
	}

	fetcher := &LocalFetcher{}
	ctx := context.Background()

	repo, err := fetcher.Fetch(ctx, tmpDir, FetchOptions{})
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if repo.Platform != "local" {
		t.Errorf("Platform = %q, want %q", repo.Platform, "local")
	}

	// Should have main.go and internal/lib.go but not binary.dat
	if len(repo.Files) != 2 {
		t.Errorf("len(Files) = %d, want 2 (got keys: %v)", len(repo.Files), fileKeys(repo.Files))
	}
	if _, ok := repo.Files["main.go"]; !ok {
		t.Error("Files missing main.go")
	}
	if _, ok := repo.Files["internal/lib.go"]; !ok {
		t.Error("Files missing internal/lib.go")
	}
	if string(repo.Files["main.go"]) != "package main\n" {
		t.Errorf("main.go content = %q, want %q", string(repo.Files["main.go"]), "package main\n")
	}
}

func TestLocalFetcherSubPath(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "root.go"), []byte("package root\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "sub", "inner.go"), []byte("package sub\n"), 0644); err != nil {
		t.Fatal(err)
	}

	fetcher := &LocalFetcher{}
	ctx := context.Background()

	repo, err := fetcher.Fetch(ctx, tmpDir, FetchOptions{SubPath: "sub"})
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	// Should only have files under sub/
	if len(repo.Files) != 1 {
		t.Errorf("len(Files) = %d, want 1 (got keys: %v)", len(repo.Files), fileKeys(repo.Files))
	}
}

func TestRateLimitRetry(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			// First attempt: rate limited
			resetTime := time.Now().Add(1 * time.Second).Unix()
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message":"rate limit exceeded"}`))
			return
		}
		// Second attempt: success
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	fetcher := &GitHubFetcher{BaseURL: server.URL}
	ctx := context.Background()

	body, _, err := fetcher.githubAPI(ctx, "/test", "")
	if err != nil {
		t.Fatalf("githubAPI failed: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp)
	}

	got := atomic.LoadInt32(&attempts)
	if got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestIsBinaryExtension(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"main.go", false},
		{"lib.py", false},
		{"README.md", false},
		{"image.png", true},
		{"photo.jpg", true},
		{"archive.zip", true},
		{"binary.exe", true},
		{"lib.so", true},
		{"icon.svg", true},
		{"file.wasm", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isBinaryExtension(tt.path)
			if got != tt.want {
				t.Errorf("isBinaryExtension(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func fileKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
