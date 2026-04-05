package meta

import (
	"context"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

func collectFindings(ch <-chan scan.Finding) []scan.Finding {
	var findings []scan.Finding
	for f := range ch {
		findings = append(findings, f)
	}
	return findings
}

func boolPtr(b bool) *bool {
	return &b
}

func makeSkillMD(yaml string) []byte {
	return []byte("---\n" + yaml + "\n---\n\nSome description here.\n")
}

func TestRunMeta(t *testing.T) {
	tests := []struct {
		name          string
		files         map[string][]byte
		paranoia      scan.ParanoiaLevel
		wantCount     int            // expected number of findings (-1 to skip count check)
		wantSeverity  string         // if set, at least one finding must have this severity
		wantContains  string         // if set, at least one finding message must contain this
		wantZero      bool           // if true, expect exactly zero findings
	}{
		{
			name: "valid SKILL.md with all fields and matching permissions",
			files: map[string][]byte{
				"SKILL.md": makeSkillMD(`name: my-skill
description: A test skill
version: 1.0.0
author: test
requires:
  network: true
  filesystem: true
  bins:
    - curl`),
				"main.go": []byte(`package main
import "net/http"
func main() { http.Get("http://example.com"); os.WriteFile("f", nil, 0644); exec.Command("curl") }
`),
			},
			paranoia: scan.ParanoiaFamily,
			wantZero: true,
		},
		{
			name: "network=false but code has http.Get",
			files: map[string][]byte{
				"SKILL.md": makeSkillMD(`name: my-skill
description: A test skill
version: 1.0.0
requires:
  network: false`),
				"main.go": []byte(`package main
func main() { http.Get("http://example.com") }
`),
			},
			paranoia:     scan.ParanoiaFamily,
			wantCount:    -1,
			wantSeverity: scan.SevMedium,
			wantContains: "Network access detected",
		},
		{
			name: "no filesystem declared but code has os.WriteFile",
			files: map[string][]byte{
				"SKILL.md": makeSkillMD(`name: my-skill
description: A test skill
version: 1.0.0`),
				"main.go": []byte(`package main
func main() { os.WriteFile("f", nil, 0644) }
`),
			},
			paranoia:     scan.ParanoiaFamily,
			wantCount:    -1,
			wantSeverity: scan.SevMedium,
			wantContains: "Filesystem access detected",
		},
		{
			name: "exec.Command but no bins declared",
			files: map[string][]byte{
				"SKILL.md": makeSkillMD(`name: my-skill
description: A test skill
version: 1.0.0`),
				"main.go": []byte(`package main
import "os/exec"
func main() { exec.Command("rm", "-rf", "/") }
`),
			},
			paranoia:     scan.ParanoiaFamily,
			wantCount:    -1,
			wantSeverity: scan.SevHigh,
			wantContains: "Process execution detected",
		},
		{
			name:         "missing SKILL.md at family paranoia",
			files:        map[string][]byte{"main.go": []byte("package main")},
			paranoia:     scan.ParanoiaFamily,
			wantCount:    1,
			wantSeverity: scan.SevLow,
			wantContains: "No SKILL.md file found",
		},
		{
			name:         "missing SKILL.md at paranoid paranoia",
			files:        map[string][]byte{"main.go": []byte("package main")},
			paranoia:     scan.ParanoiaParanoid,
			wantCount:    1,
			wantSeverity: scan.SevHigh,
			wantContains: "No SKILL.md file found",
		},
		{
			name: "SKILL.md missing required name field",
			files: map[string][]byte{
				"SKILL.md": makeSkillMD(`description: A test skill
version: 1.0.0`),
			},
			paranoia:     scan.ParanoiaFamily,
			wantCount:    -1,
			wantSeverity: scan.SevLow,
			wantContains: "missing required field: name",
		},
		{
			name: "no permission mismatches - zero findings",
			files: map[string][]byte{
				"SKILL.md": makeSkillMD(`name: my-skill
description: A test skill
version: 1.0.0`),
				"main.go": []byte(`package main
func main() { println("hello") }
`),
			},
			paranoia: scan.ParanoiaFamily,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fetch.Repo{
				Platform: "github",
				Owner:    "test",
				Name:     "test-repo",
				Files:    tt.files,
			}
			opts := scan.Options{Paranoia: tt.paranoia}
			ch := make(chan scan.Finding, 100)

			go func() {
				Run(context.Background(), repo, opts, ch)
				close(ch)
			}()
			findings := collectFindings(ch)

			if tt.wantZero {
				if len(findings) != 0 {
					t.Errorf("expected zero findings, got %d: %+v", len(findings), findings)
				}
				return
			}

			if tt.wantCount >= 0 && len(findings) != tt.wantCount {
				t.Errorf("expected %d findings, got %d: %+v", tt.wantCount, len(findings), findings)
			}

			if tt.wantSeverity != "" {
				found := false
				for _, f := range findings {
					if f.Severity == tt.wantSeverity {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected at least one finding with severity %s, got: %+v", tt.wantSeverity, findings)
				}
			}

			if tt.wantContains != "" {
				found := false
				for _, f := range findings {
					if contains(f.Message, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected at least one finding containing %q, got: %+v", tt.wantContains, findings)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
