package scan

import "testing"

const sampleRuleYAML = `id: sc-reverse-shell
kind: pattern
scanner: supplychain
category: network
severity: CRITICAL
message: Reverse shell pattern detected
patterns:
  - regex: 'foo'
`

func TestClassifyFile(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content []byte
		want    FileRole
	}{
		{"go source", "internal/scanner/supplychain/supplychain.go", nil, RoleCode},
		{"go test", "internal/scanner/supplychain/supplychain_test.go", nil, RoleTest},
		{"testfixture dir", "internal/testfixture/fixtures.go", nil, RoleTest},
		{"testdata dir", "internal/scanner/cve/testdata/deps.json", nil, RoleTest},
		{"js test", "src/foo.test.ts", nil, RoleTest},
		{"python test", "pkg/test_helper.py", nil, RoleTest},
		{"readme", "README.md", nil, RoleDoc},
		{"changelog", "CHANGELOG.md", nil, RoleDoc},
		{"docs dir", "docs/INSTALLATION.md", nil, RoleDoc},
		{"superpowers plan", "docs/superpowers/plans/2026-04-05-x.md", nil, RoleDoc},
		{"license", "LICENSE", nil, RoleDoc},
		{"skill manifest is not doc", "SKILL.md", nil, RoleCode},
		{"ci workflow", ".github/workflows/release.yml", nil, RoleConfig},
		{"json config", "config.json", nil, RoleConfig},
		{"rule yaml", "rules/supplychain/patterns/reverse_shell.yaml", []byte(sampleRuleYAML), RoleRules},
		{"non-rule yaml is config", "config/app.yaml", []byte("server:\n  port: 8080\n"), RoleConfig},
		{"plain source", "main.py", nil, RoleCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyFile(c.path, c.content)
			if got != c.want {
				t.Errorf("ClassifyFile(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestClassifyFileBackslashPaths(t *testing.T) {
	if got := ClassifyFile(`internal\scanner\foo_test.go`, nil); got != RoleTest {
		t.Errorf("backslash path: got %v, want RoleTest", got)
	}
}

func TestAdjustSeverity(t *testing.T) {
	cases := []struct {
		role    FileRole
		raw     string
		wantSev string
		wantOK  bool
	}{
		{RoleCode, SevCritical, SevCritical, true},
		{RoleConfig, SevHigh, SevHigh, true},
		{RoleTest, SevCritical, "", false},
		{RoleRules, SevCritical, "", false},
		{RoleDoc, SevCritical, SevMedium, true},
		{RoleDoc, SevHigh, SevLow, true},
		{RoleDoc, SevMedium, SevInfo, true},
		{RoleDoc, SevLow, "", false},
		{RoleDoc, SevInfo, "", false},
	}
	for _, c := range cases {
		gotSev, gotOK := AdjustSeverity(c.raw, c.role)
		if gotSev != c.wantSev || gotOK != c.wantOK {
			t.Errorf("AdjustSeverity(%s, %v) = (%q, %v), want (%q, %v)",
				c.raw, c.role, gotSev, gotOK, c.wantSev, c.wantOK)
		}
	}
}

func TestApplyFileRoles(t *testing.T) {
	files := map[string][]byte{
		"README.md":                     []byte("# doc"),
		"internal/foo_test.go":           []byte("package x"),
		"rules/x.yaml":                   []byte(sampleRuleYAML),
		"internal/foo.go":                []byte("package x"),
	}
	findings := []Finding{
		{Check: "supplychain", Severity: SevCritical, File: "README.md", Message: "doc match"},
		{Check: "skillsafety", Severity: SevHigh, File: "internal/foo_test.go", Message: "test fixture"},
		{Check: "supplychain", Severity: SevCritical, File: "rules/x.yaml", Message: "own rule"},
		{Check: "supplychain", Severity: SevHigh, File: "internal/foo.go", Message: "real code"},
		{Check: "attestation", Severity: SevHigh, File: "", Message: "no file"},
	}
	got := ApplyFileRoles(findings, files)

	// test-file and rule-file findings dropped; doc downgraded; code + no-file kept.
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(got), got)
	}
	bySev := map[string]string{}
	for _, f := range got {
		bySev[f.Message] = f.Severity
	}
	if bySev["doc match"] != SevMedium {
		t.Errorf("doc match severity = %q, want MEDIUM", bySev["doc match"])
	}
	if bySev["real code"] != SevHigh {
		t.Errorf("real code severity = %q, want HIGH", bySev["real code"])
	}
	if bySev["no file"] != SevHigh {
		t.Errorf("no-file finding severity = %q, want HIGH (unchanged)", bySev["no file"])
	}
}
