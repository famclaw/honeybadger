package skillsafety

import (
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// isBinaryContent checks for null bytes in the first 512 bytes of content.
func isBinaryContent(data []byte) bool {
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

var (
	urlRe  = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `\)]+`)
	execRe = regexp.MustCompile(`curl\s+-.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh`)
)

const SensitivePathRuleID = "ss-sensitive-paths"

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

	if rs := opts.Rules; rs != nil {
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
				if r.ID == SensitivePathRuleID {
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
	}

	var sig Signals
	sig.FileCount = len(repo.Files)

	// Find SKILL.md (case-insensitive).
	var skillContent []byte
	for path, content := range repo.Files {
		if strings.EqualFold(path, "SKILL.md") {
			skillContent = content
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

	// Scan all text-like files for override phrases and other signals.
	// Test fixtures and honeybadger's own rule corpus define attack patterns
	// by design, and Markdown prose merely describes them — none constitute a
	// live threat, so the signal pass restricts itself to real code/config and
	// to code blocks within documentation.
	isAppRepo := scan.IsApplicationRepo(repo.Files)
	for path, content := range repo.Files {
		// Skip binary files (null-byte detection).
		if isBinaryContent(content) {
			continue
		}

		// Skip test files and rule corpus (fixtures, not threats).
		role := scan.ClassifyFile(path, content)
		switch role {
		case scan.RoleTest, scan.RoleRules:
			continue
		}

		// Skip non-text files (no known extension and not 90%+ printable).
		if !scan.IsMarkdown(path) && !scan.IsTextFile(path, content) {
			continue
		}

		// For injection detection (override phrases), scan ALL text including
		// prose in any .md file, since an attacker can reference a .md file
		// containing the actual malicious instructions. This is the security fix.
		// For exfil-intent correlation, only code blocks are scanned (original behavior).
		s := string(content)
		codeOnly := s
		if role == scan.RoleDoc && scan.IsMarkdown(path) {
			codeOnly = string(scan.CodeBlockOnly(content))
		}
		fileLines := strings.Split(s, "\n")

		// Scan for override phrases in all text files (not just SKILL.md body).
		for i, line := range fileLines {
			for _, pat := range activeOverridePatterns {
				if loc := pat.re.FindString(line); loc != "" {
					sig.OverridePhrases = append(sig.OverridePhrases, Match{
						Pattern:     pat.re.String(),
						Text:        loc,
						File:        path,
						Line:        i + 1,
						RuleID:      pat.ruleID,
						MoreInfoURL: pat.moreInfoURL,
						References:  pat.references,
					})
				}
			}
		}

		// The exfil-intent correlation (sensitive paths + URLs) is meaningful
		// within a skill's small script bundle; across a compiled application's
		// source tree it only produces category-error noise, so it is skipped
		// for application repos. Exec-instruction detection below is a separate
		// signal and runs regardless.
		if !isAppRepo {
			for _, ds := range activeSensitivePaths {
				for _, sp := range ds.entries {
					if strings.Contains(codeOnly, sp) {
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

			// External URLs (scan only code blocks in docs).
			for _, u := range urlRe.FindAllString(codeOnly, -1) {
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
		}

		// Exec instructions (scan all text for all files).
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
