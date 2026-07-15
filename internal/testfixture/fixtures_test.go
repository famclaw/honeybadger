package testfixture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/engine"
	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/fetch"
)

func TestCleanRepo(t *testing.T) {
	repo := CleanRepo()
	assertRepoValid(t, repo)

	if _, ok := repo.Files["main.go"]; !ok {
		t.Error("CleanRepo missing main.go")
	}
	if _, ok := repo.Files["go.mod"]; !ok {
		t.Error("CleanRepo missing go.mod")
	}
	if _, ok := repo.Files["LICENSE"]; !ok {
		t.Error("CleanRepo missing LICENSE")
	}
}

func TestSecretsRepo(t *testing.T) {
	repo := SecretsRepo()
	assertRepoValid(t, repo)

	configGo, ok := repo.Files["config.go"]
	if !ok {
		t.Fatal("SecretsRepo missing config.go")
	}
	if !strings.Contains(string(configGo), "AKIA") {
		t.Error("SecretsRepo config.go does not contain runtime-built AWS key prefix")
	}
}

func TestSupplyChainRepo(t *testing.T) {
	repo := SupplyChainRepo()
	assertRepoValid(t, repo)

	if _, ok := repo.Files["install.sh"]; !ok {
		t.Error("SupplyChainRepo missing install.sh")
	}
	if _, ok := repo.Files["package.json"]; !ok {
		t.Error("SupplyChainRepo missing package.json")
	}
}

func TestCVERepo(t *testing.T) {
	repo := CVERepo()
	assertRepoValid(t, repo)

	if _, ok := repo.Files["requirements.txt"]; !ok {
		t.Error("CVERepo missing requirements.txt")
	}
}

func TestMetaMismatchRepo(t *testing.T) {
	repo := MetaMismatchRepo()
	assertRepoValid(t, repo)

	if _, ok := repo.Files["SKILL.md"]; !ok {
		t.Error("MetaMismatchRepo missing SKILL.md")
	}
}

func TestAttestationRepo(t *testing.T) {
	repo := AttestationRepo()
	assertRepoValid(t, repo)

	if repo.Platform != "github" {
		t.Errorf("AttestationRepo platform = %q, want github", repo.Platform)
	}
	if repo.Owner != "test" {
		t.Errorf("AttestationRepo owner = %q, want test", repo.Owner)
	}
}

func TestFullyCleanSkillRepo(t *testing.T) {
	repo := FullyCleanSkillRepo()
	assertRepoValid(t, repo)

	if _, ok := repo.Files["SKILL.md"]; !ok {
		t.Error("FullyCleanSkillRepo missing SKILL.md")
	}
	if _, ok := repo.Files["LICENSE"]; !ok {
		t.Error("FullyCleanSkillRepo missing LICENSE")
	}
}

func TestPoisonedMCPSourceRepo(t *testing.T) {
	r := PoisonedMCPSourceRepo()
	if len(r.Files) == 0 {
		t.Fatal("PoisonedMCPSourceRepo has no files")
	}
}

func TestDynamicMCPRepo(t *testing.T) {
	r := DynamicMCPRepo()
	if len(r.Files) == 0 {
		t.Fatal("DynamicMCPRepo has no files")
	}
}

func TestWriteToDir(t *testing.T) {
	repo := CleanRepo()
	dir := WriteToDir(t, repo)

	for path := range repo.Files {
		fullPath := filepath.Join(dir, filepath.FromSlash(path))
		info, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("WriteToDir: file %s not found: %v", path, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("WriteToDir: file %s is empty", path)
		}
	}
}

func assertRepoValid(t *testing.T, repo *fetch.Repo) {
	t.Helper()
	if repo == nil {
		t.Fatal("repo is nil")
	}
	if len(repo.Files) == 0 {
		t.Fatal("repo has no files")
	}
}

func TestCommentEnglishSafeRepo(t *testing.T) {
	repo := CommentEnglishSafeRepo()
	assertRepoValid(t, repo)

	// Load default rules
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	opts := scan.Options{
		Rules: rs,
	}

	// Build scanner list
	scanners := engine.BuildScannerList(opts)
	if len(scanners) == 0 {
		t.Fatal("No scanners built")
	}

	// Run all scanners and collect findings
	var findings []scan.Finding
	ctx := context.Background()

	// We'll use RunAll to run all scanners
	events := scan.RunAll(ctx, repo, opts, scanners)
	for e := range events {
		switch event := e.(type) {
		case scan.Finding:
			findings = append(findings, event)
		case scan.RuntimeError:
			if event.Message != "" {
				t.Errorf("Unexpected runtime error: %v", event)
			}
		}
	}

	// Apply file role adjustments to drop matches in test fixtures and rule corpus, etc.
	findings = scan.ApplyFileRoles(findings, repo.Files)

	// We expect no findings with rule ID "ss-override-english"
	var found bool
	for _, f := range findings {
		if f.RuleID == "ss-override-english" {
			found = true
			t.Errorf("Found ss-override-english finding in comment-safe repo: %v", f)
			break
		}
	}
	if found {
		t.Fatal("CommentEnglishSafeRepo should not trigger ss-override-english rule")
	}
}

func TestCommentEnglishUnsafeRepo(t *testing.T) {
	repo := CommentEnglishUnsafeRepo()
	assertRepoValid(t, repo)

	// Load default rules
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	opts := scan.Options{
		Rules: rs,
	}

	// Build scanner list
	scanners := engine.BuildScannerList(opts)
	if len(scanners) == 0 {
		t.Fatal("No scanners built")
	}

	// Run all scanners and collect findings
	var findings []scan.Finding
	ctx := context.Background()

	// We'll use RunAll to run all scanners
	events := scan.RunAll(ctx, repo, opts, scanners)
	for e := range events {
		switch event := e.(type) {
		case scan.Finding:
			findings = append(findings, event)
		case scan.RuntimeError:
			if event.Message != "" {
				t.Errorf("Unexpected runtime error: %v", event)
			}
		}
	}

	// We expect at least one finding with rule ID "ss-override-english"
	var found bool
	for _, f :=range findings {
		if f.RuleID == "ss-override-english" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CommentEnglishUnsafeRepo should trigger ss-override-english rule; got %d findings: %v", len(findings), findings)
	}
}

func TestBinarySafeTextFileRepo(t *testing.T) {
	repo := BinarySafeTextFileRepo()
	assertRepoValid(t, repo)

	// Load default rules
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	opts := scan.Options{
		Rules: rs,
	}

	// Build scanner list
	scanners := engine.BuildScannerList(opts)
	if len(scanners) == 0 {
		t.Fatal("No scanners built")
	}

	// Run all scanners and collect findings
	var findings []scan.Finding
	ctx := context.Background()

	// We'll use RunAll to run all scanners
	events := scan.RunAll(ctx, repo, opts, scanners)
	for e := range events {
		switch event := e.(type) {
		case scan.Finding:
			findings = append(findings, event)
		case scan.RuntimeError:
			if event.Message != "" {
				t.Errorf("Unexpected runtime error: %v", event)
			}
		}
	}

	// We expect no findings with rule ID "sc-committed-binary"
	var found bool
	for _, f := range findings {
		if f.RuleID == "sc-committed-binary" {
			found = true
			t.Errorf("Found sc-committed-binary finding in binary-safe text repo: %v", f)
			break
		}
	}
	if found {
		t.Fatal("BinarySafeTextFileRepo should not trigger sc-committed-binary rule")
	}
}

func TestBinaryUnsafeBinaryFileRepo(t *testing.T) {
	repo := BinaryUnsafeBinaryFileRepo()
	assertRepoValid(t, repo)

	// Load default rules
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	opts := scan.Options{
		Rules: rs,
	}

	// Build scanner list
	scanners := engine.BuildScannerList(opts)
	if len(scanners) == 0 {
		t.Fatal("No scanners built")
	}

	// Run all scanners and collect findings
	var findings []scan.Finding
	ctx := context.Background()

	// We'll use RunAll to run all scanners
	events := scan.RunAll(ctx, repo, opts, scanners)
	for e := range events {
		switch event := e.(type) {
		case scan.Finding:
			findings = append(findings, event)
		case scan.RuntimeError:
			if event.Message != "" {
				t.Errorf("Unexpected runtime error: %v", event)
			}
		}
	}

	// We expect no findings with rule ID "sc-committed-binary" because binary files are skipped.
	var found bool
	for _, f := range findings {
		if f.RuleID == "sc-committed-binary" {
			found = true
			t.Errorf("Found sc-committed-binary finding in binary-unsafe repo: %v", f)
			break
		}
	}
	if found {
		t.Fatal("BinaryUnsafeBinaryFileRepo should not trigger sc-committed-binary rule (binary files are skipped)")
	}
}
