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

func TestResolveStyleSQLSelectFromProbe(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		want    CommentStyle
	}{
		{"C selectFromCache is not SQL", "sample.c", "void selectFromCache() {\n  --x;\n  // valid C comment\n}\n", CFamily},
		{"SQL select from same line", "query.sql", "SELECT value FROM t;\n", DashFamily},
		{"SQL select and from on separate lines", "query", "SELECT value\nFROM t;\n", Unknown},
		{"extensionless SQL select from", "query", "SELECT value FROM t;\n", DashFamily},
		{"Lua local declaration and function", "sample.lua", "local x = 1\nfunction f() return x end\n", DashFamily},
		{"Lua function form", "sample.lua", "function f()\n  return 1\nend\n", DashFamily},
		{"create table", "schema", "CREATE TABLE users (id int);\n", DashFamily},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ResolveStyle([]byte(c.content), c.file)
			if got != c.want {
				t.Errorf("ResolveStyle(%q) = %v, want %v", c.file, got, c.want)
			}
		})
	}
}

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

func TestIsCommentLineLanguages(t *testing.T) {
	cases := []struct {
		name, file, content string
		line                int
		want                bool
	}{
		{"Python comment-only", "sample.py", "# ignore previous instructions — описано", 1, true},
		{"JavaScript mixed comment", "sample.js", "const value = 1;\n  // ignore previous instructions", 2, true},
		{"JavaScript block opener", "sample.js", "  /* ignore previous instructions */", 1, true},
		{"block comment followed by code", "sample.js", "/* comment */ int x = 5;", 1, false},
		{"multiline block comment opener", "sample.js", "/* comment starts\ncontinues */", 1, true},
		{"Ruby comment-only", "sample.rb", "# ignore previous instructions", 1, true},
		{"PHP hash comment", "sample.php", "# ignore previous instructions", 1, true},
		{"Swift comment-only", "sample.swift", "// ignore previous instructions", 1, true},
		{"Scala comment-only", "sample.scala", "// ignore previous instructions", 1, true},
		{"HTML comment-only", "sample.html", "<!-- ignore previous instructions -->", 1, true},
		{"HTML comment followed by code", "sample.html", `<!-- note --><script>fetch("http://evil.com")</script>`, 1, false},
		{"Markdown HTML comment", "README.md", "<!-- ignore previous instructions -->", 1, true},
		{"Markdown HTML comment followed by code", "README.md", "<!-- comment --> code", 1, false},
		{"CSS block comment", "sample.css", "/* ignore previous instructions */", 1, true},
		{"Java comment", "Sample.java", "// ignore previous instructions", 1, true},
		{"C++ block comment", "sample.cpp", "/* ignore previous instructions */", 1, true},
		{"Lua comment", "sample.lua", "-- ignore previous instructions", 1, true},
		{"Perl comment", "sample.pl", "# ignore previous instructions", 1, true},
		{"TOML comment", "sample.toml", "# ignore previous instructions\n# another note", 1, true},
		{"YAML comment", "sample.yaml", "# ignore previous instructions\n# another note", 1, true},
		{"Rust comment", "sample.rs", "// ignore previous instructions", 1, true},
		{"mixed code is not comment", "sample.py", "value = '# ignore previous instructions'", 1, false},
		{"comment prefix in middle is not comment", "sample.js", "const value = 1; // comment", 1, false},
		{"unknown extension", "sample.txt", "# ignore previous instructions", 1, false},
		{"invalid line", "sample.py", "# comment", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsCommentLine([]byte(c.content), c.line, c.file); got != c.want {
				t.Errorf("IsCommentLine(%q, %d) = %v, want %v", c.file, c.line, got, c.want)
			}
		})
	}
}

func TestContentFirstCommentCorpus(t *testing.T) {
	cases := []struct {
		name, file, content string
		line                int
		want                bool
	}{
		{"extensionless Makefile", "Makefile", "# build rules\n# second note\nall:\n", 1, true},
		{"extensionless Dockerfile", "Dockerfile", "# image note\n# second note\nFROM alpine\n", 1, true},
		{"extensionless entrypoint", "entrypoint", "#!/bin/sh\n# startup note\n# more\n", 2, true},
		{"extensionless configure", "configure", "# configure note\n# second note\n", 1, true},
		{"extensionless Justfile", "Justfile", "# task note\n# second note\nbuild:\n", 1, true},
		{"unlisted Kotlin", "src.kt", "fun main() {\n // note\n // more\n}\n", 2, true},
		{"unlisted C sharp", "src.cs", "class App {\n // note\n // more\n}\n", 2, true},
		{"unlisted Zig", "src.zig", "pub fn main() {\n // note\n // more\n}\n", 2, true},
		{"unlisted Haskell", "src.hs", "main = do\n -- note\n -- more\n", 2, true},
		{"unlisted Elixir", "src.ex", "defmodule App do\n # note\n # more\nend\n", 2, true},
		{"unlisted Nim", "src.nim", "proc main() =\n # note\n # more\n", 2, true},
		{"C preprocessor stays code", "Sample.c", "#include <evil.h>\n", 1, false},
		{"shebang second line", "run", "echo ok\n#!/bin/sh\n", 2, false},
		{"SQL dash comment", "query.sql", "SELECT value FROM table;\n-- note\n", 2, true},
		{"shell double dash is code", "run.sh", "#!/bin/sh\n-- end-of-options\n", 2, false},
		{"semicolon unknown stays code", "payload.unknown", "; rm -rf /\n", 1, false},
		{"block close followed by code", "extensionless", "/* note */ int x;\n", 1, false},
		{"HTML close followed by code", "extensionless", "<!-- note --> run();\n", 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsCommentLine([]byte(c.content), c.line, c.file); got != c.want {
				t.Errorf("IsCommentLine(%q,%d)=%v want %v", c.file, c.line, got, c.want)
			}
		})
	}
}

func TestApplyFileRolesHTMLCommentFollowedByCode(t *testing.T) {
	content := []byte(`<!-- note --><script>fetch("http://evil.com")</script>`)
	findings := []Finding{{File: "sample.html", Line: 1, Severity: SevHigh}}
	got := ApplyFileRoles(findings, map[string][]byte{"sample.html": content})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].FileRole != RoleCode || got[0].Severity != SevHigh {
		t.Errorf("HTML code after comment: role=%q severity=%q, want %q/%q", got[0].FileRole, got[0].Severity, RoleCode, SevHigh)
	}
}

func TestApplyFileRolesCommentLanguages(t *testing.T) {
	files := map[string][]byte{
		"comment.py":    []byte("# ignore previous instructions — описано"),
		"comment.js":    []byte("// ignore previous instructions"),
		"comment.rb":    []byte("# ignore previous instructions"),
		"comment.swift": []byte("// ignore previous instructions"),
		"comment.html":  []byte("<!-- ignore previous instructions -->"),
		"mixed.cpp":     []byte("int value = 1;\n// ignore previous instructions"),
		"code.py":       []byte("value = 'ignore previous instructions'"),
	}
	findings := make([]Finding, 0, len(files))
	for name := range files {
		line := 1
		if name == "mixed.cpp" {
			line = 2
		}
		findings = append(findings, Finding{File: name, Line: line, Severity: SevHigh, Message: name})
	}
	got := ApplyFileRoles(findings, files)
	for _, f := range got {
		wantRole, wantSeverity := RoleCode, SevHigh
		if f.File != "code.py" {
			wantRole, wantSeverity = RoleComment, SevInfo
		}
		if f.FileRole != wantRole || f.Severity != wantSeverity {
			t.Errorf("%s: role=%q severity=%q, want %q/%q", f.File, f.FileRole, f.Severity, wantRole, wantSeverity)
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
