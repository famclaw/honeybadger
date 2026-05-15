package meta

import (
	"context"
	"fmt"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
	"gopkg.in/yaml.v3"
)

// SkillMeta represents the parsed YAML frontmatter of a SKILL.md file.
type SkillMeta struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	Author      string   `yaml:"author"`
	Tags        []string `yaml:"tags"`
	Platforms   []string `yaml:"platforms"`
	Requires    struct {
		Network      *bool             `yaml:"network"`
		Filesystem   *bool             `yaml:"filesystem"`
		Bins         []string          `yaml:"bins"`
		BinsOptional map[string]string `yaml:"bins_optional"`
		EnvOptional  map[string]string `yaml:"env_optional"`
	} `yaml:"requires"`
}

// ParseFrontmatter extracts YAML frontmatter between the first pair of --- lines.
func ParseFrontmatter(content []byte) (*SkillMeta, error) {
	s := string(content)
	lines := strings.Split(s, "\n")

	start := -1
	end := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			if start == -1 {
				start = i
			} else {
				end = i
				break
			}
		}
	}
	if start == -1 || end == -1 || end <= start+1 {
		return nil, fmt.Errorf("no YAML frontmatter found")
	}

	yamlContent := strings.Join(lines[start+1:end], "\n")
	var meta SkillMeta
	if err := yaml.Unmarshal([]byte(yamlContent), &meta); err != nil {
		return nil, fmt.Errorf("parsing YAML frontmatter: %w", err)
	}
	return &meta, nil
}

// Run scans a repository's SKILL.md for metadata issues and permission mismatches.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding, _ chan<- scan.RuntimeError) {
	// Find SKILL.md in repo files
	var skillContent []byte
	var found bool
	for path, content := range repo.Files {
		if strings.EqualFold(path, "SKILL.md") {
			skillContent = content
			found = true
			break
		}
	}

	if !found {
		sev := scan.SevLow
		switch opts.Paranoia {
		case scan.ParanoiaStrict:
			sev = scan.SevMedium
		case scan.ParanoiaParanoid:
			sev = scan.SevHigh
		}
		out <- scan.Finding{
			Type:     "finding",
			Severity: sev,
			Check:    "meta",
			Message:  "No SKILL.md file found in repository",
		}
		return
	}

	meta, err := ParseFrontmatter(skillContent)
	if err != nil {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevMedium,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  fmt.Sprintf("Failed to parse SKILL.md frontmatter: %v", err),
		}
		return
	}

	// Validate required fields
	if meta.Name == "" {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevLow,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "SKILL.md missing required field: name",
		}
	}
	if meta.Description == "" {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevLow,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "SKILL.md missing required field: description",
		}
	}
	if meta.Version == "" {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevLow,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "SKILL.md missing required field: version",
		}
	}

}
