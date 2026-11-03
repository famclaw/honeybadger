package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWriteAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write first entry
	result1 := map[string]any{
		"type":    "result",
		"verdict": "PASS",
	}
	if err := WriteAudit(path, result1); err != nil {
		t.Fatalf("WriteAudit #1: %v", err)
	}

	// Write second entry
	result2 := map[string]any{
		"type":    "result",
		"verdict": "FAIL",
	}
	if err := WriteAudit(path, result2); err != nil {
		t.Fatalf("WriteAudit #2: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := splitNonEmpty(string(data))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), string(data))
	}

	var m1, m2 map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m1); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &m2); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}

	if m1["verdict"] != "PASS" {
		t.Errorf("line 1 verdict = %v, want PASS", m1["verdict"])
	}
	if m2["verdict"] != "FAIL" {
		t.Errorf("line 2 verdict = %v, want FAIL", m2["verdict"])
	}
}

func TestWriteAuditCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "audit.jsonl")

	// Should fail because subdir doesn't exist
	err := WriteAudit(path, map[string]any{"test": true})
	if err == nil {
		t.Error("expected error when directory doesn't exist")
	}
}

// TestNewAuditRecordCarriesProvenance asserts the audit record carries a
// populated provenance block with real values: source digest, rules digest,
// policy trust decision, suppression decisions, and per-check status.
func TestNewAuditRecordCarriesProvenance(t *testing.T) {
	// Real source digest: SHA256 over path+content, the same construction
	// engine.ComputeRepoHash uses for --installed-sha.
	sum := sha256.Sum256([]byte("SKILL.mdhello-world"))
	sourceDigest := hex.EncodeToString(sum[:])

	identities := []string{"sc-curl-bash|CRITICAL|1", "SECRET_IN_CODE|HIGH|3"}
	rulesDigest := RulesDigest(identities)

	checks := map[string]string{
		"secrets": "ok",
		"cve":     "error: osv.dev unreachable",
	}

	record := NewAuditRecord(
		"FAIL",
		"Finding at HIGH severity meets or exceeds HIGH threshold",
		"secret-like value in config",
		map[string]int{"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
		2, "HIGH",
		false, "gpt-4o", true,
		"family", "family", "online", "docker",
		"2026-10-12T10:00:00Z", 1234,
		sourceDigest, rulesDigest, "/home/op/.honeybadger/rules",
		true,
		1,
		[]string{"target"}, nil,
		[]string{"SECRET_IN_CODE"},
		checks,
	)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := WriteAudit(path, record); err != nil {
		t.Fatalf("WriteAudit: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got AuditRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal audit record: %v", err)
	}

	if got.Type != "result" {
		t.Errorf("type = %q, want result", got.Type)
	}
	if got.Verdict != "FAIL" || got.KeyFinding != "secret-like value in config" {
		t.Errorf("verdict/key_finding = %q/%q, not the values passed in", got.Verdict, got.KeyFinding)
	}
	if got.CVEMaxSeverity != "HIGH" {
		t.Errorf("cve_max_severity = %q, want HIGH", got.CVEMaxSeverity)
	}
	p := got.Provenance
	if p.SourceDigest != sourceDigest {
		t.Errorf("source_digest = %q, want %q", p.SourceDigest, sourceDigest)
	}
	if p.RulesDigest != rulesDigest {
		t.Errorf("rules_digest = %q, want %q", p.RulesDigest, rulesDigest)
	}
	if p.RulesDir != "/home/op/.honeybadger/rules" {
		t.Errorf("rules_dir = %q, want the user rules dir", p.RulesDir)
	}
	if !p.PolicyTrusted {
		t.Error("policy_trusted = false, want true")
	}
	if p.Suppress.SuppressedCount != 1 {
		t.Errorf("suppress.suppressed_count = %d, want 1", p.Suppress.SuppressedCount)
	}
	if !reflect.DeepEqual(p.Suppress.Applied, []string{"target"}) {
		t.Errorf("suppress.applied = %v, want [target]", p.Suppress.Applied)
	}
	if len(p.Suppress.Ignored) != 0 {
		t.Errorf("suppress.ignored = %v, want empty", p.Suppress.Ignored)
	}
	if !reflect.DeepEqual(p.Suppress.SuppressedRules, []string{"SECRET_IN_CODE"}) {
		t.Errorf("suppress.suppressed_rules = %v, want [SECRET_IN_CODE]", p.Suppress.SuppressedRules)
	}
	if p.Checks["secrets"] != "ok" {
		t.Errorf("checks[secrets] = %q, want ok", p.Checks["secrets"])
	}
	if p.Checks["cve"] != "error: osv.dev unreachable" {
		t.Errorf("checks[cve] = %q, want the failure to be recorded", p.Checks["cve"])
	}
}

// TestNewAuditRecordNormalizesEmptyCVESeverity asserts the record never leaves
// cve_max_severity ambiguous: no CVEs decodes as "none", not "".
func TestNewAuditRecordNormalizesEmptyCVESeverity(t *testing.T) {
	record := NewAuditRecord("PASS", "r", "", map[string]int{}, 0, "", false, "", false,
		"family", "family", "online", "", "2026-10-12T10:00:00Z", 1,
		"deadbeef", "cafebabe", "", false, 0, nil, nil, nil, nil)
	if record.CVEMaxSeverity != "none" {
		t.Errorf("cve_max_severity = %q, want none", record.CVEMaxSeverity)
	}
	if record.Provenance.SourceDigest != "deadbeef" || record.Provenance.RulesDigest != "cafebabe" {
		t.Error("digest fields must round-trip through the record")
	}
}

// TestAuditRecordBackwardCompatible asserts a pre-provenance record (the old
// on-disk shape, a serialized result event) still decodes, and that a new
// record keeps every old JSON field name plus the additive provenance block.
func TestAuditRecordBackwardCompatible(t *testing.T) {
	old := `{"type":"result","verdict":"PASS","reasoning":"No findings at or above threshold","key_finding":"","finding_counts":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"cve_count":0,"cve_max_severity":"","attested":false,"llm_model":"","llm_used":false,"paranoia":"family","effective_paranoia":"family","tier":"online","sandbox":"","scanned_at":"2026-01-01T00:00:00Z","duration_ms":42}`
	var got AuditRecord
	if err := json.Unmarshal([]byte(old), &got); err != nil {
		t.Fatalf("pre-provenance record must still decode: %v", err)
	}
	if got.Verdict != "PASS" || got.Provenance.SourceDigest != "" {
		t.Error("old record must decode to its old fields with zero provenance")
	}

	record := NewAuditRecord("WARN", "r", "", map[string]int{"low": 1}, 0, "", false, "", false,
		"family", "family", "online", "", "2026-01-01T00:00:00Z", 42,
		"deadbeef", "cafebabe", "", false, 0, nil, nil, nil, nil)
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal new record: %v", err)
	}
	for _, field := range []string{
		`"type":"result"`, `"verdict"`, `"reasoning"`, `"key_finding"`,
		`"finding_counts"`, `"cve_count"`, `"cve_max_severity"`, `"attested"`,
		`"llm_model"`, `"llm_used"`, `"paranoia"`, `"effective_paranoia"`,
		`"tier"`, `"sandbox"`, `"scanned_at"`, `"duration_ms"`,
	} {
		if !strings.Contains(string(b), field) {
			t.Errorf("new record lost old field %q — on-disk shape is no longer a superset", field)
		}
	}
	if !strings.Contains(string(b), `"provenance"`) {
		t.Error("new record must carry the additive provenance block")
	}
}

// TestRulesDigest asserts the rules digest is a pure, order-insensitive
// function of the rule identities in effect.
func TestRulesDigest(t *testing.T) {
	a := RulesDigest([]string{"b|HIGH|2", "a|CRITICAL|1"})
	b := RulesDigest([]string{"a|CRITICAL|1", "b|HIGH|2"})
	if a != b {
		t.Error("digest must not depend on input order")
	}
	if len(a) != 64 {
		t.Errorf("digest must be sha256 hex (64 chars), got %d", len(a))
	}
	if a == RulesDigest([]string{"a|CRITICAL|2", "b|HIGH|2"}) {
		t.Error("digest must change when a rule identity changes")
	}
}

func splitNonEmpty(s string) []string {
	var result []string
	for _, line := range splitLines(s) {
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
