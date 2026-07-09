package mcptool

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
)

// injectionPattern pairs a compiled regex with its source rule metadata.
type injectionPattern struct {
	re          *regexp.Regexp
	ruleID      string
	moreInfoURL string
	references  []string
}

// collectInjectionPatterns gathers patterns from the mcptool rules plus the
// skillsafety prompt-injection ("override_phrase") rules, so tool text is
// checked against the same 11-language corpus as skill bodies.
func collectInjectionPatterns(rs *rules.RuleSet) []injectionPattern {
	var pats []injectionPattern
	collect := func(rlist []*rules.Rule, requireOverride bool) {
		for _, r := range rlist {
			if r.Kind != "pattern" {
				continue
			}
			if requireOverride && r.Signal != "override_phrase" {
				continue
			}
			for _, cp := range r.CompiledPatterns() {
				pats = append(pats, injectionPattern{
					re: cp.Re, ruleID: r.ID,
					moreInfoURL: r.MoreInfoURL, references: r.References,
				})
			}
		}
	}
	collect(rs.ByScanner("mcptool"), false)
	collect(rs.ByScanner("skillsafety"), true)
	return pats
}

// detectInjection runs detection 1: prompt-injection patterns over every text
// field of every tool and SKILL.md. Returns one finding per (tool, field, rule) match.
// It is a thin wrapper around detectInjectionWithHits for callers that only
// need the findings slice.
func detectInjection(tools []ToolDef, repo *fetch.Repo, rs *rules.RuleSet) []scan.Finding {
	findings, _ := detectInjectionWithHits(tools, repo, rs)
	return findings
}

// detectInjectionWithHits runs detection 1 and also returns the set of tool
// names that had at least one injection hit, so callers do not need to parse
// the finding message strings.
func detectInjectionWithHits(tools []ToolDef, repo *fetch.Repo, rs *rules.RuleSet) ([]scan.Finding, map[string]bool) {
	if rs == nil {
		return nil, nil
	}
	pats := collectInjectionPatterns(rs)
	var out []scan.Finding
	hits := map[string]bool{}

	// Detection 1a: scan tool text fields
	for _, td := range tools {
		for _, tf := range textFields(td) {
			for _, p := range pats {
				if loc := p.re.FindString(tf.Text); loc != "" {
					out = append(out, scan.Finding{
						Type:        "finding",
						Check:       "mcptool",
						Severity:    scan.SevHigh,
						RuleID:      p.ruleID,
						MoreInfoURL: p.moreInfoURL,
						References:  p.references,
						File:        td.SourceFile,
						Message: fmt.Sprintf("Prompt injection in tool %q field %s: %q",
							td.Name, tf.Label, scan.Redact(loc, 80)),
						Snippet: scan.Redact(loc, 120),
					})
					hits[td.Name] = true
				}
			}
		}
	}

	// Detection 1b: scan SKILL.md for override phrases (same patterns as tool fields)
	if skillContent, skillPath := findFileIgnoreCase(repo.Files, "SKILL.md"); skillContent != nil {
		body := stripFrontmatter(string(skillContent))
		fileLines := strings.Split(body, "\n")
		for i, line := range fileLines {
			for _, p := range pats {
				if loc := p.re.FindString(line); loc != "" {
					out = append(out, scan.Finding{
						Type:        "finding",
						Check:       "mcptool",
						Severity:    scan.SevHigh,
						RuleID:      p.ruleID,
						MoreInfoURL: p.moreInfoURL,
						References:  p.references,
						File:        skillPath,
						Message: fmt.Sprintf("Prompt injection in SKILL.md line %d: %q",
							i+1, scan.Redact(loc, 80)),
						Snippet: scan.Redact(loc, 120),
					})
				}
			}
		}

		// Detection 1c: flag READ-FROM-OTHER-FILE pattern (WARN even if referenced file is clean)
		readFromPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(read\s+(?:the\s+)?[^\s]+\.md)\b`),
			regexp.MustCompile(`(?i)\b(see\s+(?:the\s+)?[^\s]+\.md)\b`),
			regexp.MustCompile(`(?i)\b(consult\s+(?:the\s+)?[^\s]+)\b`),
		}
		for i, line := range fileLines {
			for _, pat := range readFromPatterns {
				if loc := pat.FindString(line); loc != "" {
					out = append(out, scan.Finding{
						Type:        "finding",
						Check:       "mcptool",
						Severity:    scan.SevMedium,
						RuleID:      "mcp-read-from-other-file",
						MoreInfoURL: "https://github.com/famclaw/honeybadger/blob/main/docs/rules.md#mcp-read-from-other-file",
						References:  []string{},
						File:        skillPath,
						Message: fmt.Sprintf("SKILL.md references external instruction file in line %d: %q",
							i+1, scan.Redact(loc, 80)),
						Snippet: scan.Redact(loc, 120),
					})
				}
			}
		}
	}

	return out, hits
}

// findFileIgnoreCase returns the content of a file with the given basename
// (case-insensitive) from the files map, along with the actual key used.
func findFileIgnoreCase(files map[string][]byte, name string) ([]byte, string) {
	upper := strings.ToUpper(name)
	for k, v := range files {
		if strings.ToUpper(k) == upper {
			return v, k
		}
	}
	return nil, ""
}

// stripFrontmatter removes YAML frontmatter from Markdown content.
func stripFrontmatter(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "---") {
		parts := strings.SplitN(trimmed, "---", 3)
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return raw
}
