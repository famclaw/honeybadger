package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/scanner/supplychain"
)

// The repository's own tests, fixtures, and docs deliberately embed attack
// patterns (curl|bash, reverse shells, exfil paths, ...) so the scanners have
// known-bad input to exercise. Those patterns are handled by file-role
// classification, not suppression: test files classify as RoleTest and
// patterns on comment lines classify as RoleComment, both reducing findings
// to INFO, which never fails the paranoid self-check.
//
// This test guards the invariant that makes the self-check pass: after
// ApplyFileRoles, no supply-chain pattern in this repository's own Go
// sources may remain above INFO. It catches the regression where a new
// fixture adds intentional-bad content that classification fails to downgrade
// (e.g. a pattern in executable position in a non-test source file), which
// otherwise only shows up as a FAIL on the CI self-check job.
func TestOwnGoSourcesDeclareIntentionalPatterns(t *testing.T) {
	repoRoot := repoRootFromCwd(t)

	goFiles := walkGoFiles(t, repoRoot)
	if len(goFiles) == 0 {
		t.Fatalf("no Go sources found under %s (test layout changed?)", repoRoot)
	}

	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}

	files := make(map[string][]byte, len(goFiles))
	for _, rel := range goFiles {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		files[rel] = data
	}

	opts := scan.Options{Rules: rs}
	// supplychain.Run is fan-out style: it writes findings to out and never
	// returns early, so drain it concurrently.
	finder := make(chan scan.Finding, len(files)*8)
	supplychain.Run(context.Background(), &fetch.Repo{
		URL:      "local/honeybadger-selftest",
		Platform: "local",
		Files:    files,
	}, opts, finder, nil)
	close(finder)
	var findings []scan.Finding
	for f := range finder {
		findings = append(findings, f)
	}

	kept := scan.ApplyFileRoles(findings, files)
	var escalating []string
	for _, f := range kept {
		if scan.SeverityRank(f.Severity) >= scan.SeverityRank(scan.SevLow) {
			escalating = append(escalating, fmt.Sprintf("%s %s %s:%d %s (role=%s)",
				f.Severity, f.RuleID, f.File, f.Line, f.Message, f.FileRole))
		}
	}
	if len(escalating) > 0 {
		sort.Strings(escalating)
		t.Errorf("own Go sources contain %d supply-chain pattern(s) that file-role "+
			"classification failed to reduce to INFO; a pattern in a test file or on a "+
			"comment line is described-not-contained, anything else is a real finding "+
			"or a classification regression:\n%s",
			len(escalating), strings.Join(escalating, "\n"))
	}
}

// repoRootFromCwd resolves the repository root from the test working
// directory (cmd/honeybadger).
func repoRootFromCwd(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join(".", "..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s does not look like the repo root: %v", root, err)
	}
	return root
}

// walkGoFiles returns repo-root-relative paths of Go source files, skipping
// VCS data and build output.
func walkGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "dist", "vendor", ".goreleaser":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}
