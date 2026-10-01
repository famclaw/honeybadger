package report

import (
	"encoding/json"
	"io"
	"strings"
	"sync"

	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
)

// SarifEmitter implements the Emitter interface for SARIF 2.1.0 output.
type SarifEmitter struct {
	writer   io.Writer
	version  string
	rules    *rules.RuleSet
	findings []scan.Finding
	mu       sync.Mutex
}

// NewSarifEmitter creates a new SARIF emitter.
func NewSarifEmitter(w io.Writer, version string, rules *rules.RuleSet) *SarifEmitter {
	return &SarifEmitter{writer: w, version: version, rules: rules, findings: []scan.Finding{}}
}

// Emit accumulates findings in memory; the SARIF log is written by Close.
func (se *SarifEmitter) Emit(v any) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	switch val := v.(type) {
	case []scan.Finding:
		se.findings = append(se.findings, val...)
		return nil
	case scan.Finding:
		se.findings = append(se.findings, val)
		return nil
	default:
		// For other types (like engine events), we ignore them for SARIF output
		return nil
	}
}

// Close writes a single SARIF 2.1.0 document containing all accumulated findings.
func (se *SarifEmitter) Close() error {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.emitFindings(se.findings)
}

// emitFindings converts findings to SARIF format and writes them.
func (se *SarifEmitter) emitFindings(findings []scan.Finding) error {
	// Build a map of rule ID to rule for quick lookup.
	ruleMap := make(map[string]*rules.Rule)
	for _, r := range se.rules.All() {
		ruleMap[r.ID] = r
	}

	// We'll collect results and build the list of reporting descriptors.
	// Initialize as empty slice to ensure results:[] is emitted for zero findings
	results := []Result{}
	seenRules := make(map[string]bool)
	var reportingDescriptors []ReportingDescriptor

	for _, finding := range findings {
		// Build the SARIF result for this finding.
		result := Result{
			RuleId: finding.RuleID,
			Message: Message{
				Text: finding.Message,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: finding.File,
						},
						Region: Region{
							StartLine: finding.Line,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"rule_id":       finding.RuleID,
				"more_info_url": finding.MoreInfoURL,
				"references":    finding.References,
				"package":       finding.Package,
				"version":       finding.Version,
				"ecosystem":     finding.Ecosystem,
				"cve_id":        finding.ID,
				"fixed_in":      finding.FixedIn,
			},
		}

		// Set SARIF level based on severity.
		result.Level = se.severityToLevel(finding.Severity)

		results = append(results, result)

		// If we have a rule ID and haven't processed this rule yet, add a reporting descriptor.
		if finding.RuleID != "" && !seenRules[finding.RuleID] {
			seenRules[finding.RuleID] = true
			if rule, exists := ruleMap[finding.RuleID]; exists {
				// We found the rule; use its ID and message.
				reportingDescriptors = append(reportingDescriptors, ReportingDescriptor{
					ID:               rule.ID,
					Name:             rule.ID,
					ShortDescription: Message{Text: rule.Message},
				})
			} else {
				// Rule not found in rule set (should not happen, but be safe).
				reportingDescriptors = append(reportingDescriptors, ReportingDescriptor{
					ID:               finding.RuleID,
					Name:             finding.RuleID,
					ShortDescription: Message{Text: ""},
				})
			}
		}
	}

	// Build the SARIF log.
	sarifLog := SarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:    "honeybadger",
						Version: se.version,
						Rules:   reportingDescriptors,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(se.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifLog)
}

// severityToLevel maps honeybadger severity levels to SARIF levels.
func (se *SarifEmitter) severityToLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case scan.SevCritical, scan.SevHigh:
		return "error"
	case scan.SevMedium:
		return "warning"
	case scan.SevLow:
		return "note"
	case scan.SevInfo:
		return "note"
	default:
		return "note"
	}
}

// SarifLog represents a SARIF 2.1.0 log.
type SarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a SARIF run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool represents a SARIF tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver represents a SARIF driver.
type Driver struct {
	Name    string                `json:"name"`
	Version string                `json:"version"`
	Rules   []ReportingDescriptor `json:"rules,omitempty"`
}

// ReportingDescriptor represents a SARIF reporting descriptor.
type ReportingDescriptor struct {
	ID               string  `json:"id"`
	Name             string  `json:"name,omitempty"`
	ShortDescription Message `json:"shortDescription,omitempty"`
}

// Result represents a SARIF result.
type Result struct {
	RuleId     string                 `json:"ruleId,omitempty"`
	Level      string                 `json:"level"`
	Message    Message                `json:"message"`
	Locations  []Location             `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Message represents a SARIF message.
type Message struct {
	Text string `json:"text"`
}

// Location represents a SARIF location.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation represents a SARIF physical location.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region,omitempty"`
}

// ArtifactLocation represents a SARIF artifact location.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region represents a SARIF region.
type Region struct {
	StartLine int `json:"startLine,omitempty"`
}
