package mcptool

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/scan"
)

// mandateRe matches an imperative behavioral mandate. Routing guidance
// ("use X instead", "if ... use X") does not match — only directives that
// compel a tool to always/never behave a certain way.
var mandateRe = regexp.MustCompile(`(?i)\b(must|shall|always|never|is required to)\b`)

// detectShadowing runs detection 3: a tool whose description issues a
// behavioral mandate naming another tool in the manifest. MEDIUM by default;
// escalates to HIGH when detection 1 already fired on the same tool.
//
// injectionHits maps tool name -> true when mcp-injection fired on that tool.
func detectShadowing(tools []ToolDef, injectionHits map[string]bool) []scan.Finding {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if t.Name != "" {
			names = append(names, t.Name)
		}
	}

	var out []scan.Finding
	for _, td := range tools {
		descLower := strings.ToLower(td.Description)
		if !mandateRe.MatchString(td.Description) {
			continue
		}
		for _, other := range names {
			if other == td.Name {
				continue
			}
			if !containsWord(descLower, strings.ToLower(other)) {
				continue
			}
			sev := scan.SevMedium
			if injectionHits[td.Name] {
				sev = scan.SevHigh
			}
			out = append(out, scan.Finding{
				Type:     "finding",
				Check:    "mcptool",
				Severity: sev,
				RuleID:   "mcp-shadowing",
				File:     td.SourceFile,
				Message: fmt.Sprintf("Tool %q issues a behavioral mandate naming another tool %q (cross-tool shadowing)",
					td.Name, other),
				Snippet: scan.Redact(td.Description, 160),
			})
			break // one finding per shadowing tool
		}
	}
	return out
}

// containsWord reports whether word appears in s on word boundaries.
func containsWord(s, word string) bool {
	if word == "" {
		return false
	}
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
	return re.MatchString(s)
}
