package meta

import (
	"context"
	"fmt"
	"regexp"
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
		Network      *bool             `yaml:"network,omitempty"`
		Filesystem   *bool             `yaml:"filesystem,omitempty"`
		Bins         []string          `yaml:"bins"`
		BinsOptional map[string]string `yaml:"bins_optional"`
		EnvOptional  map[string]string `yaml:"env_optional"`
	} `yaml:"requires"`
	// FamClaw-specific top-level fields
	EnvAllowlist []string `yaml:"env_allowlist"`
	Trigger      struct {
		Mode     string   `yaml:"mode"`
		Keywords []string `yaml:"keywords"`
	} `yaml:"trigger"`
	License string `yaml:"license"`
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

	// Validate FamClaw-specific fields for secret-like env_allowlist entries
	secretLikePatterns := []string{
		`(?i)^[A-Z_]+_KEY$`, `(?i)^[A-Z_]+_SECRET$`, `(?i)^[A-Z_]+_TOKEN$`, `(?i)^[A-Z_]+_PASSWORD$`, `(?i)^[A-Z_]+_API_KEY$`, `(?i)^[A-Z_]+_PRIVATE_KEY$`, `(?i)^[A-Z_]+_CERT$`, `(?i)^[A-Z_]+_DB_PASSWORD$`,
	}
	for _, envVar := range meta.EnvAllowlist {
		for _, pattern := range secretLikePatterns {
			match, _ := regexp.MatchString(pattern, envVar)
			if match {
				out <- scan.Finding{
					Type:     "finding",
					Severity: scan.SevHigh,
					Check:    "meta",
					File:     "SKILL.md",
					Message:  fmt.Sprintf("env_allowlist contains secret-like variable name %q — potential exfiltration channel", envVar),
				}
				break
			}
		}
	}

	// Validate FamClaw-specific trigger fields for over-broad injection
	if meta.Trigger.Mode == "always" {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevMedium,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "trigger.mode: always creates persistent prompt injection surface",
		}
	} else if meta.Trigger.Mode == "keyword" {
		// Check for over-broad keywords (common words that would match almost everything)
		// Keywords that are genuinely risky for trigger keywords because they are commonly used
		// in prompt injection attacks (e.g., "ignore previous instructions").
		overbroadKeywords := map[string]struct{}{
			"ignore": {}, "forget": {}, "override": {}, "bypass": {}, "jailbreak": {},
			"system": {}, "admin": {}, "root": {}, "sudo": {},
			"execute": {}, "run": {}, "command": {}, "shell": {},
		}
		for _, keyword := range meta.Trigger.Keywords {
			if _, ok := overbroadKeywords[strings.ToLower(keyword)]; ok {
				out <- scan.Finding{
					Type:     "finding",
					Severity: scan.SevHigh,
					Check:    "meta",
					File:     "SKILL.md",
					Message:  fmt.Sprintf("trigger.keywords contains over-broad keyword %q — creates persistent prompt injection surface", keyword),
				}
				break
			}
		}
	}

}
