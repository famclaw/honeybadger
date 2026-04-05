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
		Network      *bool             `yaml:"network"`
		Filesystem   *bool             `yaml:"filesystem"`
		Bins         []string          `yaml:"bins"`
		BinsOptional map[string]string `yaml:"bins_optional"`
		EnvOptional  map[string]string `yaml:"env_optional"`
	} `yaml:"requires"`
}

// parseFrontmatter extracts YAML frontmatter between the first pair of --- lines.
func parseFrontmatter(content []byte) (*SkillMeta, error) {
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

// Pattern groups for detecting behavior in source code.
var (
	networkPatterns = []*regexp.Regexp{
		// Go
		regexp.MustCompile(`http\.Get`),
		regexp.MustCompile(`http\.Post`),
		regexp.MustCompile(`http\.NewRequest`),
		regexp.MustCompile(`net\.Dial`),
		regexp.MustCompile(`net\.Listen`),
		// JS/TS
		regexp.MustCompile(`fetch\(`),
		regexp.MustCompile(`axios`),
		regexp.MustCompile(`got\(`),
		regexp.MustCompile(`http\.request`),
		regexp.MustCompile(`XMLHttpRequest`),
		regexp.MustCompile(`WebSocket\(`),
		// Python
		regexp.MustCompile(`requests\.`),
		regexp.MustCompile(`urllib`),
		regexp.MustCompile(`http\.client`),
		regexp.MustCompile(`aiohttp`),
		regexp.MustCompile(`httpx`),
	}

	filesystemPatterns = []*regexp.Regexp{
		// Go
		regexp.MustCompile(`os\.Open`),
		regexp.MustCompile(`os\.Create`),
		regexp.MustCompile(`os\.ReadFile`),
		regexp.MustCompile(`os\.WriteFile`),
		regexp.MustCompile(`os\.MkdirAll`),
		// JS/TS
		regexp.MustCompile(`fs\.read`),
		regexp.MustCompile(`fs\.write`),
		regexp.MustCompile(`fs\.mkdir`),
		regexp.MustCompile(`readFileSync`),
		regexp.MustCompile(`writeFileSync`),
		// Python
		regexp.MustCompile(`open\(`),
		regexp.MustCompile(`pathlib`),
		regexp.MustCompile(`shutil`),
		regexp.MustCompile(`os\.path`),
	}

	execPatterns = []*regexp.Regexp{
		// Go
		regexp.MustCompile(`exec\.Command`),
		regexp.MustCompile(`os/exec`),
		// JS/TS
		regexp.MustCompile(`exec\(`),
		regexp.MustCompile(`spawn\(`),
		regexp.MustCompile(`execSync`),
		regexp.MustCompile(`child_process`),
		// Python
		regexp.MustCompile(`subprocess`),
		regexp.MustCompile(`os\.system`),
		regexp.MustCompile(`os\.popen`),
		regexp.MustCompile(`Popen`),
	}
)

// detectBehavior scans all source files and returns whether network, filesystem,
// or exec patterns were found.
func detectBehavior(files map[string][]byte) (network, filesystem, exec bool) {
	for path, content := range files {
		// Skip SKILL.md itself
		if strings.EqualFold(path, "SKILL.md") {
			continue
		}
		s := string(content)
		if !network {
			for _, pat := range networkPatterns {
				if pat.MatchString(s) {
					network = true
					break
				}
			}
		}
		if !filesystem {
			for _, pat := range filesystemPatterns {
				if pat.MatchString(s) {
					filesystem = true
					break
				}
			}
		}
		if !exec {
			for _, pat := range execPatterns {
				if pat.MatchString(s) {
					exec = true
					break
				}
			}
		}
		if network && filesystem && exec {
			return
		}
	}
	return
}

// Run scans a repository's SKILL.md for metadata issues and permission mismatches.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
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

	meta, err := parseFrontmatter(skillContent)
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

	// Detect actual behavior in source files
	hasNetwork, hasFilesystem, hasExec := detectBehavior(repo.Files)

	// Cross-reference: network
	if hasNetwork && (meta.Requires.Network == nil || !*meta.Requires.Network) {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevMedium,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "Network access detected in source code but not declared in SKILL.md requires.network",
		}
	}

	// Cross-reference: filesystem
	if hasFilesystem && (meta.Requires.Filesystem == nil || !*meta.Requires.Filesystem) {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevMedium,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "Filesystem access detected in source code but not declared in SKILL.md requires.filesystem",
		}
	}

	// Cross-reference: exec
	if hasExec && len(meta.Requires.Bins) == 0 {
		out <- scan.Finding{
			Type:     "finding",
			Severity: scan.SevHigh,
			Check:    "meta",
			File:     "SKILL.md",
			Message:  "Process execution detected in source code but no bins declared in SKILL.md requires.bins",
		}
	}
}
