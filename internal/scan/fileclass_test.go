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
		{"go test", "internal/scanner/supplychain/supplychain_test.go", nil, RoleUnknown},
		{"testfixture dir", "internal/testfixture/fixtures.go", nil, RoleUnknown},
		{"testdata dir", "internal/scanner/cve/testdata/deps.json", nil, RoleUnknown},
		{"js test", "src/foo.test.ts", nil, RoleUnknown},
		{"python test", "pkg/test_helper.py", nil, RoleUnknown},
		{"readme", "README.md", nil, RoleProse},
		{"changelog", "CHANGELOG.md", nil, RoleProse},
		{"docs dir", "docs/INSTALLATION.md", nil, RoleProse},
		{"superpowers plan", "docs/superpowers/plans/2026-04-05-x.md", nil, RoleProse},
		{"license", "LICENSE", nil, RoleProse},
		{"skill manifest is not doc", "SKILL.md", nil, RoleCode},
		{"skill.md inside testdata is a fixture", "internal/testdata/skills/SKILL.md", nil, RoleUnknown},
		{"ci workflow", ".github/workflows/release.yml", nil, RoleUnknown},
		{"json config", "config.json", nil, RoleUnknown},
		{"rule yaml", "rules/supplychain/patterns/reverse_shell.yaml", []byte(sampleRuleYAML), RoleUnknown},
		{"non-rule yaml is config", "config/app.yaml", []byte("server:\n  port: 8080\n"), RoleUnknown},
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
	if got := ClassifyFile(`internal\scanner\foo_test.go`, nil); got != RoleUnknown {
		t.Errorf("backslash path: got %v, want RoleUnknown", got)
	}
}

func TestAdjustSeverity(t *testing.T) {
	cases := []struct {
		role    FileRole
		raw     string
		wantSev string
	}{
		{RoleCode, SevCritical, SevCritical},
		{RoleUnknown, SevHigh, SevHigh},
		{RoleProse, SevCritical, SevMedium},
		{RoleProse, SevHigh, SevLow},
		{RoleProse, SevMedium, SevInfo},
		{RoleProse, SevLow, SevInfo},
		{RoleProse, SevInfo, SevInfo},
		{RoleComment, SevCritical, SevInfo},
		{RoleComment, SevMedium, SevInfo},
	}
	for _, c := range cases {
		got := AdjustSeverity(c.raw, c.role)
		if got != c.wantSev {
			t.Errorf("AdjustSeverity(%q, %q) = %q, want %q", c.raw, c.role, got, c.wantSev)
		}
	}
}

func TestApplyFileRoles(t *testing.T) {
	files := map[string][]byte{
		"README.md":            []byte("# doc"),
		"internal/foo_test.go": []byte("package x"),
		"rules/x.yaml":         []byte(sampleRuleYAML),
		"internal/foo.go":      []byte("package x"),
	}
	findings := []Finding{
		{Check: "supplychain", Severity: SevCritical, File: "README.md", Message: "doc match"},
		{Check: "skillsafety", Severity: SevHigh, File: "internal/foo_test.go", Message: "test fixture"},
		{Check: "supplychain", Severity: SevCritical, File: "rules/x.yaml", Message: "own rule"},
		{Check: "supplychain", Severity: SevHigh, File: "internal/foo.go", Message: "real code"},
		{Check: "attestation", Severity: SevHigh, File: "", Message: "no file"},
	}
	got := ApplyFileRoles(findings, files)

	// No drops: all 5 findings are retained with FileRole and adjusted severity.
	if len(got) != 5 {
		t.Fatalf("got %d findings, want 5: %+v", len(got), got)
	}
	byMsg := map[string]Finding{}
	for _, f := range got {
		byMsg[f.Message] = f
	}
	if f := byMsg["doc match"]; f.FileRole != RoleProse || f.Severity != SevMedium {
		t.Errorf("doc match: role=%q sev=%q, want prose/MEDIUM", f.FileRole, f.Severity)
	}
	if f := byMsg["test fixture"]; f.FileRole != RoleUnknown || f.Severity != SevHigh {
		t.Errorf("test fixture: role=%q sev=%q, want unknown/HIGH", f.FileRole, f.Severity)
	}
	if f := byMsg["own rule"]; f.FileRole != RoleUnknown || f.Severity != SevCritical {
		t.Errorf("own rule: role=%q sev=%q, want unknown/CRITICAL", f.FileRole, f.Severity)
	}
	if f := byMsg["real code"]; f.FileRole != RoleCode || f.Severity != SevHigh {
		t.Errorf("real code: role=%q sev=%q, want code/HIGH", f.FileRole, f.Severity)
	}
	if f := byMsg["no file"]; f.FileRole != RoleUnknown || f.Severity != SevHigh {
		t.Errorf("no file: role=%q sev=%q, want unknown/HIGH", f.FileRole, f.Severity)
	}
}

func TestApplyFileRolesMarkdown(t *testing.T) {
	md := []byte("prose mentioning curl|bash\n\n```\ncurl x | sh\n```\n")
	// line 1 = prose, line 4 = inside code fence
	files := map[string][]byte{"README.md": md}
	findings := []Finding{
		{Check: "supplychain", Severity: SevCritical, File: "README.md", Line: 1, Message: "prose match"},
		{Check: "supplychain", Severity: SevHigh, File: "README.md", Line: 4, Message: "code-block match"},
		{Check: "secrets", Severity: SevHigh, File: "README.md", Message: "no line info"},
	}
	got := ApplyFileRoles(findings, files)

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(got), got)
	}
	byMsg := map[string]Finding{}
	for _, f := range got {
		byMsg[f.Message] = f
	}
	if f := byMsg["prose match"]; f.FileRole != RoleProse || f.Severity != SevMedium {
		t.Errorf("prose match: role=%q sev=%q, want prose/MEDIUM", f.FileRole, f.Severity)
	}
	if f := byMsg["code-block match"]; f.FileRole != RoleProse || f.Severity != SevInfo {
		t.Errorf("code-block match: role=%q sev=%q, want prose/INFO", f.FileRole, f.Severity)
	}
	if f := byMsg["no line info"]; f.FileRole != RoleProse || f.Severity != SevLow {
		t.Errorf("no line info: role=%q sev=%q, want prose/LOW", f.FileRole, f.Severity)
	}
}

func TestIsRuleYAMLFile(t *testing.T) {
	rule := []byte(sampleRuleYAML)
	plain := []byte("server:\n  port: 8080\n")
	cases := []struct {
		name    string
		path    string
		content []byte
		want    bool
	}{
		{"lowercase yaml rule", "rules/supplychain/patterns/reverse_shell.yaml", rule, true},
		{"uppercase YAML rule", "rules/FOO.YAML", rule, true},
		{"uppercase YML rule", "rules/Bar.YML", rule, true},
		{"mixed case Yaml rule", "rules/Baz.Yaml", rule, true},
		{"backslash uppercase rule", `rules\FOO.YAML`, rule, true},
		{"non-rule yaml", "config/app.yaml", plain, false},
		{"non-rule uppercase yaml", "config/APP.YAML", plain, false},
		{"non-yaml extension", "rules/FOO.txt", rule, false},
		{"empty content", "rules/FOO.YAML", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsRuleYAMLFile(c.path, c.content); got != c.want {
				t.Errorf("IsRuleYAMLFile(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestIsApplicationRepo(t *testing.T) {
	cases := []struct {
		name  string
		files map[string][]byte
		want  bool
	}{
		{"go app", map[string][]byte{
			"go.mod": {}, "main.go": {}, "a.go": {}, "b.go": {},
		}, true},
		{"rust app", map[string][]byte{
			"Cargo.toml": {}, "src/main.rs": {}, "src/a.rs": {}, "src/b.rs": {},
		}, true},
		{"maven app", map[string][]byte{
			"pom.xml": {}, "A.java": {}, "B.java": {}, "C.java": {},
		}, true},
		{"skill bundle", map[string][]byte{"SKILL.md": {}, "helper.sh": {}}, false},
		{"python skill", map[string][]byte{"SKILL.md": {}, "pyproject.toml": {}}, false},
		{"empty", map[string][]byte{}, false},
		// Anti-evasion: a lone build manifest dropped into a skill bundle must
		// not disable the skill scanners — it needs real compiled source too.
		{"token go.mod cannot fake an app", map[string][]byte{
			"go.mod": {}, "SKILL.md": {}, "helper.sh": {},
		}, false},
		{"manifest with too little source", map[string][]byte{
			"go.mod": {}, "main.go": {},
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsApplicationRepo(c.files); got != c.want {
				t.Errorf("IsApplicationRepo(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
