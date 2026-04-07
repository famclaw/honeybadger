// Package skillsafety extracts structured signals from skill files
// for safety evaluation. It detects prompt injection, Unicode obfuscation,
// data exfiltration intent, and multi-language hiding attacks.
package skillsafety

// Signals is the structured output from skill file analysis.
type Signals struct {
	OverridePhrases   []Match  `json:"override_phrases"`
	RoleOverrides     []Match  `json:"role_overrides"`
	SensitivePaths    []string `json:"sensitive_paths"`
	ExternalURLs      []string `json:"external_urls"`
	WebhookURLs       []string `json:"webhook_urls"`
	ExecInstructions  []Match  `json:"exec_instructions"`
	HasCurlInProse    bool     `json:"has_curl_in_prose"`
	HasSetupScript    bool     `json:"has_setup_script"`
	ZeroWidthChars    int      `json:"zero_width_chars"`
	RTLOverrides      int      `json:"rtl_overrides"`
	HomoglyphWords    []string `json:"homoglyph_words"`
	HTMLComments      []string `json:"html_comments"`
	LanguagesDetected []string `json:"languages_detected"`
	PrimaryLanguage   string   `json:"primary_language"`
	UnexpectedScripts []string `json:"unexpected_scripts"`
	SkillName         string   `json:"skill_name"`
	HasFrontmatter    bool     `json:"has_frontmatter"`
	BodyTokenEstimate int      `json:"body_token_estimate"`
	FileCount         int      `json:"file_count"`
}

// Match records where a signal was found.
type Match struct {
	Pattern string `json:"pattern"`
	Text    string `json:"text"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}
