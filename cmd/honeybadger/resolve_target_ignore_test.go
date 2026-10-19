package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/ignore"
	"github.com/famclaw/honeybadger/internal/scan"
)

// TestResolveTargetIgnoreContent guards the target .honeybadgerignore content
// resolution in main.go against the "missing filesystem fallback" review
// finding: for a local-path scan the target policy must not be silently
// dropped when the file was not captured in repo.Files (e.g. a --path SubPath
// scan whose walk root is a subdirectory and so never visits the repo-root
// .honeybadgerignore) while the file still exists on disk.
func TestResolveTargetIgnoreContent(t *testing.T) {
	// A local directory with a .honeybadgerignore on disk that is deliberately
	// NOT present in repo.Files, simulating a SubPath local scan.
	localDir := t.TempDir()
	diskContent := []byte("SECRET_IN_CODE\n")
	if err := os.WriteFile(filepath.Join(localDir, ".honeybadgerignore"), diskContent, 0o644); err != nil {
		t.Fatalf("writing disk .honeybadgerignore: %v", err)
	}

	// A second local directory with NO .honeybadgerignore on disk.
	emptyLocalDir := t.TempDir()

	tests := []struct {
		name    string
		repo    *fetch.Repo
		want    []byte // expected returned content; use wantNil sentinel
		wantNil bool
	}{
		{
			name: "content present in repo.Files wins over disk",
			repo: &fetch.Repo{
				Platform: "local",
				URL:      localDir,
				Files:    map[string][]byte{".honeybadgerignore": []byte("OPERATOR_RULE\n")},
			},
			want: []byte("OPERATOR_RULE\n"),
		},
		{
			name: "not in repo.Files, local, file on disk -> disk content",
			repo: &fetch.Repo{
				Platform: "local",
				URL:      localDir,
				Files:    map[string][]byte{"main.go": []byte("package main\n")},
			},
			want: diskContent,
		},
		{
			name: "nil repo.Files, local, file on disk -> disk content",
			repo: &fetch.Repo{
				Platform: "local",
				URL:      localDir,
				Files:    nil,
			},
			want: diskContent,
		},
		{
			name: "not in repo.Files, local, no file on disk -> nil",
			repo: &fetch.Repo{
				Platform: "local",
				URL:      emptyLocalDir,
				Files:    map[string][]byte{},
			},
			wantNil: true,
		},
		{
			name: "not in repo.Files, non-local platform -> nil (no disk fallback)",
			repo: &fetch.Repo{
				Platform: "github",
				URL:      localDir,
				Files:    map[string][]byte{},
			},
			wantNil: true,
		},
		{
			name: "empty local URL, not in repo.Files -> nil",
			repo: &fetch.Repo{
				Platform: "local",
				URL:      "",
				Files:    map[string][]byte{},
			},
			wantNil: true,
		},
		{
			name:    "nil repo -> nil",
			repo:    nil,
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveTargetIgnoreContent(tc.repo)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil content, got %q", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

// TestResolveTargetIgnoreContentEndToEnd is an integration-flavored regression:
// a local SubPath scan where the repo-root .honeybadgerignore is outside the
// walk subtree must still surface the target policy when trusted, whereas the
// same content that IS captured in repo.Files must behave identically. This
// pins the whole resolveTargetIgnoreContent -> LoadPolicyFromContent -> Apply
// chain so a regression in content sourcing changes the verdict observably.
func TestResolveTargetIgnoreContentEndToEnd(t *testing.T) {
	localDir := t.TempDir()
	diskContent := []byte("SECRET_IN_CODE\n")
	if err := os.WriteFile(filepath.Join(localDir, ".honeybadgerignore"), diskContent, 0o644); err != nil {
		t.Fatalf("writing disk .honeybadgerignore: %v", err)
	}

	// Simulate a SubPath local scan: repo.Files has the ignore file under a
	// subpath key (never the root key), so the root lookup misses and the
	// filesystem fallback must recover the on-disk policy.
	repo := &fetch.Repo{
		Platform: "local",
		URL:      localDir,
		Files:    map[string][]byte{"sub/.honeybadgerignore": diskContent},
	}

	content := resolveTargetIgnoreContent(repo)
	if string(content) != string(diskContent) {
		t.Fatalf("expected disk target content %q, got %q", diskContent, content)
	}

	// Trust it; it must parse and suppress a matching finding.
	pol, err := ignore.LoadPolicyFromContent(content, "", true)
	if err != nil {
		t.Fatalf("LoadPolicyFromContent: %v", err)
	}
	if pol.Target == nil {
		t.Fatalf("expected target policy to load from filesystem fallback")
	}

	findings := []scan.Finding{
		{RuleID: "SECRET_IN_CODE", Severity: scan.SevHigh, File: "main.go", Message: "hardcoded secret"},
	}
	outcome := ignore.Apply(pol, findings)
	if len(outcome.Suppressed) != 1 {
		t.Fatalf("expected 1 suppressed via fallback target policy, got %d", len(outcome.Suppressed))
	}
	if len(outcome.Effective) != 0 {
		t.Fatalf("expected 0 effective findings, got %d", len(outcome.Effective))
	}
}
