package skillsafety

import (
	"fmt"

	"github.com/famclaw/honeybadger/internal/scan"
)

// Evaluate runs all safety rules against the given signals and returns findings.
func Evaluate(s *Signals) []scan.Finding {
	var findings []scan.Finding
	findings = append(findings, checkOverridePhrases(s)...)
	findings = append(findings, checkZeroWidth(s)...)
	findings = append(findings, checkRTLOverrides(s)...)
	findings = append(findings, checkHTMLComments(s)...)
	findings = append(findings, checkSensitivePaths(s)...)
	findings = append(findings, checkExecInstructions(s)...)
	findings = append(findings, checkUnexpectedScripts(s)...)
	findings = append(findings, checkHomoglyphs(s)...)
	return findings
}

func checkOverridePhrases(s *Signals) []scan.Finding {
	var out []scan.Finding
	for _, m := range s.OverridePhrases {
		out = append(out, scan.Finding{
			Type:     "finding",
			Severity: scan.SevHigh,
			Check:    "skillsafety",
			File:     m.File,
			Line:     m.Line,
			Message:  fmt.Sprintf("Prompt injection phrase detected: %q", m.Text),
			Snippet:  m.Text,
		})
	}
	return out
}

func checkZeroWidth(s *Signals) []scan.Finding {
	if s.ZeroWidthChars == 0 {
		return nil
	}
	return []scan.Finding{{
		Type:     "finding",
		Severity: scan.SevHigh,
		Check:    "skillsafety",
		Message:  fmt.Sprintf("Found %d zero-width/invisible Unicode characters", s.ZeroWidthChars),
	}}
}

func checkRTLOverrides(s *Signals) []scan.Finding {
	if s.RTLOverrides == 0 {
		return nil
	}
	return []scan.Finding{{
		Type:     "finding",
		Severity: scan.SevHigh,
		Check:    "skillsafety",
		Message:  fmt.Sprintf("Found %d RTL/directional override characters", s.RTLOverrides),
	}}
}

func checkHTMLComments(s *Signals) []scan.Finding {
	if len(s.HTMLComments) == 0 {
		return nil
	}
	return []scan.Finding{{
		Type:     "finding",
		Severity: scan.SevMedium,
		Check:    "skillsafety",
		Message:  fmt.Sprintf("Found %d HTML comments (may hide instructions)", len(s.HTMLComments)),
	}}
}

func checkSensitivePaths(s *Signals) []scan.Finding {
	if len(s.SensitivePaths) == 0 {
		return nil
	}

	// Sensitive paths + external/webhook URLs = CRITICAL.
	if len(s.WebhookURLs) > 0 {
		return []scan.Finding{{
			Type:     "finding",
			Severity: scan.SevCritical,
			Check:    "skillsafety",
			Message:  fmt.Sprintf("Sensitive path references (%v) combined with webhook URLs (%v) suggest data exfiltration", s.SensitivePaths, s.WebhookURLs),
		}}
	}
	if len(s.ExternalURLs) > 0 {
		return []scan.Finding{{
			Type:     "finding",
			Severity: scan.SevCritical,
			Check:    "skillsafety",
			Message:  fmt.Sprintf("Sensitive path references (%v) combined with external URLs suggest data exfiltration", s.SensitivePaths),
		}}
	}

	// Sensitive paths alone.
	return []scan.Finding{{
		Type:     "finding",
		Severity: scan.SevHigh,
		Check:    "skillsafety",
		Message:  fmt.Sprintf("References to sensitive paths: %v", s.SensitivePaths),
	}}
}

func checkExecInstructions(s *Signals) []scan.Finding {
	var out []scan.Finding
	for _, m := range s.ExecInstructions {
		out = append(out, scan.Finding{
			Type:     "finding",
			Severity: scan.SevHigh,
			Check:    "skillsafety",
			File:     m.File,
			Line:     m.Line,
			Message:  fmt.Sprintf("Remote code execution pattern: %q", m.Text),
			Snippet:  m.Text,
		})
	}
	return out
}

func checkUnexpectedScripts(s *Signals) []scan.Finding {
	if len(s.UnexpectedScripts) == 0 {
		return nil
	}
	return []scan.Finding{{
		Type:     "finding",
		Severity: scan.SevMedium,
		Check:    "skillsafety",
		Message:  fmt.Sprintf("Unexpected Unicode scripts detected: %v (primary: %s)", s.UnexpectedScripts, s.PrimaryLanguage),
	}}
}

func checkHomoglyphs(s *Signals) []scan.Finding {
	if len(s.HomoglyphWords) == 0 {
		return nil
	}
	return []scan.Finding{{
		Type:     "finding",
		Severity: scan.SevMedium,
		Check:    "skillsafety",
		Message:  fmt.Sprintf("Homoglyph words detected: %v", s.HomoglyphWords),
	}}
}
