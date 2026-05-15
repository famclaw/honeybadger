package mcptool

import (
	"fmt"
	"regexp"

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
// field of every tool. Returns one finding per (tool, field, rule) match.
// It is a thin wrapper around detectInjectionWithHits for callers that only
// need the findings slice.
func detectInjection(tools []ToolDef, rs *rules.RuleSet) []scan.Finding {
	findings, _ := detectInjectionWithHits(tools, rs)
	return findings
}

// detectInjectionWithHits runs detection 1 and also returns the set of tool
// names that had at least one injection hit, so callers do not need to parse
// the finding message strings.
func detectInjectionWithHits(tools []ToolDef, rs *rules.RuleSet) ([]scan.Finding, map[string]bool) {
	if rs == nil {
		return nil, nil
	}
	pats := collectInjectionPatterns(rs)
	var out []scan.Finding
	hits := map[string]bool{}
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
	return out, hits
}
