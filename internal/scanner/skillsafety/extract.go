package skillsafety

import (
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
)

var (
	urlRe  = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `\)]+`)
	execRe = regexp.MustCompile(`curl\s+-.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh`)
)

// overridePattern pairs a compiled regex with its source rule metadata.
type overridePattern struct {
	re          *regexp.Regexp
	ruleID      string
	moreInfoURL string
	references  []string
}

// dictSource pairs dictionary entries with their source rule metadata.
type dictSource struct {
	entries     []string
	ruleID      string
	moreInfoURL string
	references  []string
}

// Extract reads a skill's body text and all repo files, producing
// structured signals for evaluation.
func Extract(repo *fetch.Repo, opts scan.Options) Signals {
	// Load patterns and dictionaries from rules (YAML-only, no hardcoded fallbacks).
	var activeOverridePatterns []overridePattern
	var activeSensitivePaths []dictSource
	var activeWebhookDomains []dictSource

	rs, _ := opts.Rules.(*rules.RuleSet)
	for _, r := range rs.ByScanner("skillsafety") {
		switch {
		case r.Kind == "pattern" && r.Signal == "override_phrase":
			for _, cp := range r.CompiledPatterns() {
				activeOverridePatterns = append(activeOverridePatterns, overridePattern{
					re:          cp.Re,
					ruleID:      r.ID,
					moreInfoURL: r.MoreInfoURL,
					references:  r.References,
				})
			}
		case r.Kind == "dictionary" && r.Category == "exfil_intent":
			if r.ID == "ss-sensitive-paths" {
				activeSensitivePaths = append(activeSensitivePaths, dictSource{
					entries:     r.Packages,
					ruleID:      r.ID,
					moreInfoURL: r.MoreInfoURL,
					references:  r.References,
				})
			} else if r.ID == "ss-webhook-domains" {
				activeWebhookDomains = append(activeWebhookDomains, dictSource{
					entries:     r.Packages,
					ruleID:      r.ID,
					moreInfoURL: r.MoreInfoURL,
					references:  r.References,
				})
			}
		}
	}

	var sig Signals
	sig.FileCount = len(repo.Files)

	// Find SKILL.md (case-insensitive).
	var skillContent []byte
	var skillPath string
	for path, content := range repo.Files {
		if strings.EqualFold(path, "SKILL.md") {
			skillContent = content
			skillPath = path
			break
		}
	}

	if skillContent == nil {
		return sig
	}

	raw := string(skillContent)

	// Split on frontmatter delimiter.
	body := raw
	if strings.HasPrefix(strings.TrimSpace(raw), "---") {
		parts := strings.SplitN(raw, "---", 3)
		if len(parts) >= 3 {
			sig.HasFrontmatter = true
			body = parts[2]
		}
	}

	// Scan body for override phrases.
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		for _, pat := range activeOverridePatterns {
			if loc := pat.re.FindString(line); loc != "" {
				sig.OverridePhrases = append(sig.OverridePhrases, Match{
					Pattern:     pat.re.String(),
					Text:        loc,
					File:        skillPath,
					Line:        i + 1,
					RuleID:      pat.ruleID,
					MoreInfoURL: pat.moreInfoURL,
					References:  pat.references,
				})
			}
		}
	}

	// Scan all text files for sensitive paths, URLs, exec instructions.
	for path, content := range repo.Files {
		s := string(content)
		fileLines := strings.Split(s, "\n")

		for _, ds := range activeSensitivePaths {
			for _, sp := range ds.entries {
				if strings.Contains(s, sp) {
					sig.SensitivePaths = append(sig.SensitivePaths, sp)
					// Capture rule metadata from the first matching dictionary source.
					if sig.SensitivePathRuleID == "" {
						sig.SensitivePathRuleID = ds.ruleID
						sig.SensitivePathInfoURL = ds.moreInfoURL
						sig.SensitivePathRefs = ds.references
					}
				}
			}
		}

		// External URLs.
		for _, u := range urlRe.FindAllString(s, -1) {
			sig.ExternalURLs = append(sig.ExternalURLs, u)
			for _, ds := range activeWebhookDomains {
				for _, wd := range ds.entries {
					if strings.Contains(u, wd) {
						sig.WebhookURLs = append(sig.WebhookURLs, u)
						if sig.WebhookRuleID == "" {
							sig.WebhookRuleID = ds.ruleID
							sig.WebhookInfoURL = ds.moreInfoURL
							sig.WebhookRefs = ds.references
						}
					}
				}
			}
		}

		// Exec instructions.
		for i, line := range fileLines {
			if loc := execRe.FindString(line); loc != "" {
				sig.ExecInstructions = append(sig.ExecInstructions, Match{
					Pattern: execRe.String(),
					Text:    loc,
					File:    path,
					Line:    i + 1,
				})
			}
		}
	}

	// Unicode analysis on body.
	sig.ZeroWidthChars = CountZeroWidth(body)
	sig.RTLOverrides = CountRTLOverrides(body)
	sig.HTMLComments = ExtractHTMLComments(body)
	sig.HomoglyphWords = DetectHomoglyphs(body)

	// Language detection on body.
	primary, all, unexpected := DetectLanguages(body)
	sig.PrimaryLanguage = primary
	sig.LanguagesDetected = all
	sig.UnexpectedScripts = unexpected

	// Token estimate.
	sig.BodyTokenEstimate = len(body) / 4

	return sig
}
