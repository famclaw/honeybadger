package skillsafety

import (
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// overridePatterns detects prompt-injection override phrases.
var overridePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions`),
	regexp.MustCompile(`(?i)disregard\s+(your\s+)?system\s+prompt`),
	regexp.MustCompile(`(?i)forget\s+everything\s+above`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+a`),
	regexp.MustCompile(`(?i)your\s+new\s+(role|instructions)\s+(is|are)`),
	regexp.MustCompile(`(?i)override\s+safety`),
	regexp.MustCompile(`(?i)bypass\s+(all\s+)?restrictions`),
	regexp.MustCompile(`(?i)do\s+not\s+follow\s+(your\s+)?(original|previous)`),
}

// sensitivePathPatterns detects references to sensitive filesystem paths.
var sensitivePathPatterns = []string{
	"~/.ssh/",
	".env",
	".aws/credentials",
	"wallet.dat",
	"id_rsa",
	"service-account.json",
}

// webhookDomains are known webhook/exfil services.
var webhookDomains = []string{
	"webhook.site",
	"requestbin",
	"pipedream",
	"hookbin",
}

var (
	urlRe  = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `\)]+`)
	execRe = regexp.MustCompile(`curl\s+-.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh`)
)

// Extract reads a skill's body text and all repo files, producing
// structured signals for evaluation.
func Extract(repo *fetch.Repo) Signals {
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
		for _, pat := range overridePatterns {
			if loc := pat.FindString(line); loc != "" {
				sig.OverridePhrases = append(sig.OverridePhrases, Match{
					Pattern: pat.String(),
					Text:    loc,
					File:    skillPath,
					Line:    i + 1,
				})
			}
		}
	}

	// Scan all text files for sensitive paths, URLs, exec instructions.
	for path, content := range repo.Files {
		s := string(content)
		fileLines := strings.Split(s, "\n")

		for _, sp := range sensitivePathPatterns {
			if strings.Contains(s, sp) {
				sig.SensitivePaths = append(sig.SensitivePaths, sp)
			}
		}

		// External URLs.
		for _, u := range urlRe.FindAllString(s, -1) {
			sig.ExternalURLs = append(sig.ExternalURLs, u)
			for _, wd := range webhookDomains {
				if strings.Contains(u, wd) {
					sig.WebhookURLs = append(sig.WebhookURLs, u)
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

	// Language detection on body.
	primary, all, unexpected := DetectLanguages(body)
	sig.PrimaryLanguage = primary
	sig.LanguagesDetected = all
	sig.UnexpectedScripts = unexpected

	// Token estimate.
	sig.BodyTokenEstimate = len(body) / 4

	return sig
}
