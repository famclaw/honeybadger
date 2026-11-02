package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Provenance is the machine-readable provenance block appended to every
// audit record. It lets a downstream approver or auditor answer, from the
// record alone: what exactly was scanned (SourceDigest), which rule set was
// in effect (RulesDigest / RulesDir), how suppression was decided
// (PolicyTrusted / Suppress), and which checks completed versus failed
// (Checks). All fields are additive — an old consumer that reads only the
// verdict fields ignores the block.
type Provenance struct {
	// SourceDigest is the SHA256 of the scanned repository content
	// (engine.ComputeRepoHash), identical to the value --installed-sha
	// compares against.
	SourceDigest string `json:"source_digest"`
	// RulesDigest is the SHA256 of the loaded rule set, one line per rule
	// (id + severity + pattern count), sorted by rule ID.
	RulesDigest string `json:"rules_digest"`
	// RulesDir is the user rule directory that was merged over the
	// embedded rules; empty when only embedded rules were in effect.
	RulesDir string `json:"rules_dir,omitempty"`
	// PolicyTrusted records the trust decision for the target-authored
	// .honeybadgerignore (the --trust-target-ignore flag or
	// HONEYBADGER_TRUST_TARGET_IGNORE=1).
	PolicyTrusted bool `json:"policy_trusted"`
	// Suppress captures the suppression decisions applied to findings.
	Suppress SuppressDecision `json:"suppress"`
	// Checks maps scanner name to "ok" or "error: <message>". Every
	// scanner in the scanner list appears; a failed scanner therefore
	// cannot masquerade as a completed check.
	Checks map[string]string `json:"checks"`
}

// SuppressDecision records what .honeybadgerignore did to the findings.
type SuppressDecision struct {
	// SuppressedCount is the number of findings removed by suppression.
	SuppressedCount int `json:"suppressed_count"`
	// Applied lists suppression sources that took effect (e.g. "target",
	// "operator").
	Applied []string `json:"applied,omitempty"`
	// Ignored lists suppression sources that were present but not trusted
	// (e.g. a target .honeybadgerignore without --trust-target-ignore).
	Ignored []string `json:"ignored,omitempty"`
	// SuppressedRules lists the rule IDs (or glob/sha256 patterns) of the
	// suppression rules that actually matched findings, in first-match
	// order.
	SuppressedRules []string `json:"suppressed_rules,omitempty"`
}

// AuditRecord is the on-disk JSONL audit record. The leading fields mirror
// engine.ResultEvent field-for-field (same names, same tags) so the on-disk
// shape is a strict superset of the pre-provenance record: records written
// before the provenance block was added remain decodable and readable by
// existing consumers, and new records keep "type":"result" so consumers that
// key on that field are unaffected. Provenance is the additive block.
type AuditRecord struct {
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
	// Provenance is the additive provenance block (see Provenance).
	Provenance Provenance `json:"provenance"`
}

// NewAuditRecord builds an AuditRecord from the final-result values (the
// same values that populate engine.ResultEvent) plus the provenance inputs
// gathered during the scan. The returned record is ready for WriteAudit.
func NewAuditRecord(
	verdict, reasoning, keyFinding string,
	findingCounts map[string]int,
	cveCount int, cveMaxSeverity string,
	attested bool, llmModel string, llmUsed bool,
	paranoia, effectiveParanoia, tier, sandbox string,
	scannedAt string, durationMS int64,
	sourceDigest, rulesDigest, rulesDir string,
	policyTrusted bool,
	suppressedCount int,
	applied, ignored []string,
	suppressedRules []string,
	checks map[string]string,
) *AuditRecord {
	if suppressedRules == nil {
		suppressedRules = []string{}
	}
	if checks == nil {
		checks = map[string]string{}
	}
	return &AuditRecord{
		Type:              "result",
		Verdict:           verdict,
		Reasoning:         reasoning,
		KeyFinding:        keyFinding,
		FindingCounts:     findingCounts,
		CVECount:          cveCount,
		CVEMaxSeverity:    cveMaxSev(cveMaxSeverity),
		Attested:          attested,
		LLMModel:          llmModel,
		LLMUsed:           llmUsed,
		Paranoia:          paranoia,
		EffectiveParanoia: effectiveParanoia,
		Tier:              tier,
		Sandbox:           sandbox,
		ScannedAt:         scannedAt,
		DurationMS:        durationMS,
		Provenance: Provenance{
			SourceDigest:  sourceDigest,
			RulesDigest:   rulesDigest,
			RulesDir:      rulesDir,
			PolicyTrusted: policyTrusted,
			Suppress: SuppressDecision{
				SuppressedCount: suppressedCount,
				Applied:         applied,
				Ignored:         ignored,
				SuppressedRules: suppressedRules,
			},
			Checks: checks,
		},
	}
}

// cveMaxSev normalizes the empty-string "no CVEs" case into an explicit
// value so the record never leaves the field ambiguous.
func cveMaxSev(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// RulesDigest computes the provenance rules digest from a rule set: one
// "id|severity|patterns" line per rule, sorted by rule ID, SHA256-hashed.
// The identities slice is built by the caller from the loaded RuleSet
// (store must not depend on the rules package), so the digest stays a pure
// function of the rules that were in effect.
func RulesDigest(identities []string) string {
	sorted := make([]string, len(identities))
	copy(sorted, identities)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}

// WriteAudit appends a JSON line to the audit file at path.
// This is a lightweight approach compatible with future SQLite integration.
func WriteAudit(path string, result any) (retErr error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening audit file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing audit file: %w", cerr)
		}
	}()
	if err := json.NewEncoder(f).Encode(result); err != nil {
		return fmt.Errorf("encoding audit record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing audit file: %w", err)
	}
	return nil
}
