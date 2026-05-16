package capability

import (
	"context"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// runTest runs the capability scanner over an inline fixture and returns the findings + runtime errors.
func runTest(t *testing.T, files map[string][]byte) ([]scan.Finding, []scan.RuntimeError) {
	t.Helper()
	out := make(chan scan.Finding, 16)
	errs := make(chan scan.RuntimeError, 8)
	go func() {
		Run(context.Background(), &fetch.Repo{Files: files}, scan.Options{}, out, errs)
		close(out)
		close(errs)
	}()
	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}
	var rerrs []scan.RuntimeError
	for e := range errs {
		rerrs = append(rerrs, e)
	}
	return findings, rerrs
}

func TestCapability(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string][]byte
		wantRule  string // empty = expect zero findings of any drift rule
		wantSev   string
		wantRTErr bool
	}{
		{
			name: "silent_with_network",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\n---\n"),
				"main.go":  []byte("package main\nimport \"net/http\"\nfunc main(){ http.Get(\"https://example.com\") }\n"),
			},
			wantRule: "cap-net-drift", wantSev: scan.SevMedium,
		},
		{
			name: "declared_false_with_network",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\nrequires:\n  network: false\n---\n"),
				"main.go":  []byte("package main\nimport \"net/http\"\nfunc main(){ http.Get(\"https://example.com\") }\n"),
			},
			wantRule: "cap-net-drift", wantSev: scan.SevHigh,
		},
		{
			name: "declared_true_with_network",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\nrequires:\n  network: true\n---\n"),
				"main.go":  []byte("package main\nimport \"net/http\"\nfunc main(){ http.Get(\"https://example.com\") }\n"),
			},
			wantRule: "", // no drift
		},
		{
			name: "declared_false_no_evidence",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\nrequires:\n  network: false\n---\n"),
				"notes.md": []byte("just docs, no network\n"),
			},
			wantRule: "",
		},
		{
			name: "silent_with_filesystem",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\n---\n"),
				"main.py":  []byte("open(\"/etc/passwd\")\n"),
			},
			wantRule: "cap-fs-drift", wantSev: scan.SevMedium,
		},
		{
			name: "declared_false_with_filesystem",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\nrequires:\n  filesystem: false\n---\n"),
				"main.py":  []byte("open(\"/etc/passwd\")\n"),
			},
			wantRule: "cap-fs-drift", wantSev: scan.SevHigh,
		},
		{
			name: "bins_partial_declared",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\nrequires:\n  bins: [git]\n---\n"),
				"run.sh":   []byte("#!/usr/bin/env bash\ngit status\ncurl https://example.com\n"),
			},
			wantRule: "cap-bin-drift", wantSev: scan.SevMedium,
		},
		{
			name: "env_whitelisted",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\n---\n"),
				"main.go":  []byte("package main\nimport \"os\"\nfunc main(){ os.Getenv(\"PATH\"); os.Getenv(\"HOME\") }\n"),
			},
			wantRule: "",
		},
		{
			name: "env_undeclared",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nname: t\ndescription: t\n---\n"),
				"main.py":  []byte("import os\nk = os.environ[\"OPENAI_API_KEY\"]\n"),
			},
			wantRule: "cap-env-drift", wantSev: scan.SevMedium,
		},
		{
			name: "missing_skill_md",
			files: map[string][]byte{
				"main.go": []byte("package main\nfunc main(){}\n"),
			},
			wantRule: "cap-no-skill-md", wantSev: scan.SevInfo,
		},
		{
			name: "bad_frontmatter",
			files: map[string][]byte{
				"SKILL.md": []byte("---\nrequires:\n  network: ][not yaml\n---\n"),
				"main.go":  []byte("package main\nfunc main(){}\n"),
			},
			wantRTErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings, rerrs := runTest(t, tc.files)
			if tc.wantRTErr {
				if len(rerrs) == 0 {
					t.Fatalf("expected runtime error, got none; findings=%+v", findings)
				}
				return
			}
			if tc.wantRule == "" {
				for _, f := range findings {
					if strings.HasPrefix(f.RuleID, "cap-") && f.RuleID != "cap-no-skill-md" {
						t.Fatalf("expected no drift finding, got %s sev=%s msg=%s", f.RuleID, f.Severity, f.Message)
					}
				}
				return
			}
			for _, f := range findings {
				if f.RuleID == tc.wantRule {
					if tc.wantSev != "" && f.Severity != tc.wantSev {
						t.Fatalf("rule %s got sev=%s want=%s msg=%s", f.RuleID, f.Severity, tc.wantSev, f.Message)
					}
					return
				}
			}
			t.Fatalf("missing expected finding rule=%s sev=%s; got=%+v", tc.wantRule, tc.wantSev, findings)
		})
	}
}

// TestRunSkipsApplicationRepo verifies the capability scanner does not report
// drift across a compiled application's source tree: such a repo's code is the
// implementation of a tool, not an agent skill's scripts.
func TestRunSkipsApplicationRepo(t *testing.T) {
	files := map[string][]byte{
		"go.mod":   []byte("module example.com/app\n\ngo 1.22\n"),
		"SKILL.md": []byte("---\nname: t\ndescription: t\n---\n"),
		"main.go":  []byte("package main\nimport \"net/http\"\nfunc main(){ http.Get(\"https://x\") }\n"),
	}
	findings, rerrs := runTest(t, files)
	if len(rerrs) != 0 {
		t.Fatalf("unexpected runtime errors: %+v", rerrs)
	}
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "cap-") && f.RuleID != "cap-app-repo" {
			t.Fatalf("application repo should yield no drift finding, got %s: %s", f.RuleID, f.Message)
		}
		if f.Severity != scan.SevInfo {
			t.Fatalf("application-repo notice should be INFO, got %s", f.Severity)
		}
	}
}
