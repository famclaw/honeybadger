package testfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
