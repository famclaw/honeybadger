package engine

// ProgressEvent reports a phase transition during a scan.
type ProgressEvent struct {
	Type    string `json:"type"` // always "progress"
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

// NewProgressEvent constructs a ProgressEvent with the type tag set.
func NewProgressEvent(phase, message string) ProgressEvent {
	return ProgressEvent{Type: "progress", Phase: phase, Message: message}
}

// SandboxEvent reports sandbox detection results.
type SandboxEvent struct {
	Type              string `json:"type"` // always "sandbox"
	Available         bool   `json:"available"`
	Reason            string `json:"reason"`
	SandboxType       string `json:"sandbox_type"`
	EffectiveParanoia string `json:"effective_paranoia"`
}

// HealthEvent mirrors fetch.Health field-for-field plus the type tag.
type HealthEvent struct {
	Type                 string   `json:"type"` // always "health"
	Stars                int      `json:"stars"`
	Contributors         int      `json:"contributors"`
	AgeDays              int      `json:"age_days"`
	LastCommitDays       int      `json:"last_commit_days"`
	HasLicense           bool     `json:"has_license"`
	HasSecurityMD        bool     `json:"has_security_md"`
	HasSignedCommits     bool     `json:"has_signed_commits"`
	RecentOwnerChange    bool     `json:"recent_ownership_change"`
	IssuesMentioningRisk []string `json:"issues_mentioning_risk"`
}

// ResultEarlyEvent is emitted at early-exit sites (--force, installed-SHA
// match) where only the basic verdict envelope is meaningful.
type ResultEarlyEvent struct {
	Type      string `json:"type"` // always "result"
	Verdict   string `json:"verdict"`
	Reasoning string `json:"reasoning"`
}

// ResultEvent is the full final-verdict event emitted after a complete scan.
// All fields are always populated to preserve a stable NDJSON consumer shape.
type ResultEvent struct {
	Type              string         `json:"type"` // always "result"
	Verdict           string         `json:"verdict"`
	Reasoning         string         `json:"reasoning"`
	KeyFinding        string         `json:"key_finding"`
	FindingCounts     map[string]int `json:"finding_counts"`
	CVECount          int            `json:"cve_count"`
	CVEMaxSeverity    string         `json:"cve_max_severity"`
	Attested          bool           `json:"attested"`
	LLMModel          string         `json:"llm_model"`
	LLMUsed           bool           `json:"llm_used"`
	Paranoia          string         `json:"paranoia"`
	EffectiveParanoia string         `json:"effective_paranoia"`
	Tier              string         `json:"tier"`
	Sandbox           string         `json:"sandbox"`
	ScannedAt         string         `json:"scanned_at"`
	DurationMS        int64          `json:"duration_ms"`
}

// SuppressionEvent reports the count of findings suppressed by
// .honeybadgerignore.
type SuppressionEvent struct {
	Type            string `json:"type"` // always "suppression_summary"
	SuppressedCount int    `json:"suppressed_count"`
}
