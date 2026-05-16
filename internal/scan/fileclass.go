package scan

import (
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileRole classifies a repository file by what kind of artifact it is.
// Scanners and the verdict pipeline use the role to discriminate a threat
// that is *present* in executable code from one merely *described* in prose,
// embedded in a test fixture, or defined in honeybadger's own rule corpus.
type FileRole int

const (
	// RoleCode is real source: findings carry full severity.
	RoleCode FileRole = iota
	// RoleTest is a test file or fixture. Attack strings here are expected
	// test inputs, not live threats — findings are dropped.
	RoleTest
	// RoleDoc is documentation/prose. A described pattern is far weaker
	// signal than a present one — findings are downgraded.
	RoleDoc
	// RoleConfig is configuration (CI workflows, JSON/TOML/INI). Findings
	// keep their severity; scanner-specific scoping handles config noise.
	RoleConfig
	// RoleRules is a honeybadger rule definition (detection patterns by
	// design). Pattern matches here are data, not threats — findings dropped.
	RoleRules
)

// String renders the role for diagnostics.
func (r FileRole) String() string {
	switch r {
	case RoleCode:
		return "code"
	case RoleTest:
		return "test"
	case RoleDoc:
		return "doc"
	case RoleConfig:
		return "config"
	case RoleRules:
		return "rules"
	default:
		return "unknown"
	}
}

// knownScanners are the scanner names a honeybadger rule YAML may target.
var knownScanners = map[string]bool{
	"supplychain": true, "skillsafety": true, "secrets": true,
	"capability": true, "cve": true, "meta": true,
	"mcptool": true, "attestation": true,
}

// testDirSegments are path segments that mark a file as test material.
var testDirSegments = map[string]bool{
	"testdata": true, "testfixture": true, "testfixtures": true,
	"__tests__": true, "__mocks__": true,
}

// docExts are file extensions treated as documentation/prose.
var docExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".txt": true, ".adoc": true,
}

// docBasenames are extensionless files treated as documentation.
var docBasenames = map[string]bool{
	"LICENSE": true, "NOTICE": true, "AUTHORS": true, "COPYING": true,
}

// configExts are configuration file extensions.
var configExts = map[string]bool{
	".yaml": true, ".yml": true, ".toml": true, ".ini": true,
	".cfg": true, ".json": true,
}

// ClassifyFile determines the FileRole of a repository file from its path
// (relative, any OS separator) and, when available, its content. Content is
// only consulted to recognise honeybadger rule YAML; nil content is fine.
func ClassifyFile(rel string, content []byte) FileRole {
	p := strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	base := path.Base(p)
	ext := path.Ext(p)

	// Test material is classified first: a SKILL.md or rule YAML living under
	// a testdata/ tree is a deliberately crafted fixture, not a live artifact.
	if isTestPath(p, base) {
		return RoleTest
	}
	// SKILL.md is the skill manifest — the subject of analysis, not prose.
	if base == "skill.md" {
		return RoleCode
	}
	if (ext == ".yaml" || ext == ".yml") && isRuleYAML(content) {
		return RoleRules
	}
	if isDocPath(p, base, ext) {
		return RoleDoc
	}
	if configExts[ext] || strings.HasPrefix(base, "dockerfile") || hasSegment(p, ".github") {
		return RoleConfig
	}
	return RoleCode
}

func isTestPath(p, base string) bool {
	for _, seg := range strings.Split(p, "/") {
		if testDirSegments[seg] {
			return true
		}
	}
	if strings.HasSuffix(base, "_test.go") {
		return true
	}
	// JS/TS: foo.test.ts, foo.spec.js
	if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return true
	}
	// Python: test_foo.py, foo_test.py
	if strings.HasSuffix(p, ".py") &&
		(strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")) {
		return true
	}
	return false
}

func isDocPath(p, base, ext string) bool {
	if docExts[ext] {
		return true
	}
	if docBasenames[strings.ToUpper(base)] {
		return true
	}
	return hasSegment(p, "docs") || hasSegment(p, "doc")
}

func hasSegment(p, seg string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == seg {
			return true
		}
	}
	return false
}

// ruleSniff is the minimal shape of a honeybadger rule YAML.
type ruleSniff struct {
	ID      string `yaml:"id"`
	Kind    string `yaml:"kind"`
	Scanner string `yaml:"scanner"`
}

// isRuleYAML reports whether content parses as a honeybadger detection rule.
func isRuleYAML(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	var r ruleSniff
	if err := yaml.Unmarshal(content, &r); err != nil {
		return false
	}
	if r.ID == "" || !knownScanners[r.Scanner] {
		return false
	}
	return r.Kind == "pattern" || r.Kind == "dictionary"
}

// AdjustSeverity maps a finding's raw severity through the file role it was
// found in. The second return is false when the finding should be dropped.
func AdjustSeverity(raw string, role FileRole) (string, bool) {
	switch role {
	case RoleTest, RoleRules:
		return "", false
	case RoleDoc:
		// A described threat is two severity levels weaker than a present one.
		rank := SeverityRank(raw) - 2
		if rank < 1 {
			return "", false
		}
		return severityForRank(rank), true
	default: // RoleCode, RoleConfig
		return raw, true
	}
}

// severityForRank is the inverse of SeverityRank.
func severityForRank(rank int) string {
	switch rank {
	case 5:
		return SevCritical
	case 4:
		return SevHigh
	case 3:
		return SevMedium
	case 2:
		return SevLow
	case 1:
		return SevInfo
	default:
		return ""
	}
}

// appBuildManifests are filenames that mark a repository as a built,
// compiled-language application rather than an agent skill. Skills are
// SKILL.md-centric script bundles; they do not ship these.
var appBuildManifests = map[string]bool{
	"go.mod": true, "cargo.toml": true, "pom.xml": true,
	"build.gradle": true, "build.gradle.kts": true,
}

// compiledSourceExts are source extensions of compiled-language applications.
var compiledSourceExts = map[string]bool{
	".go": true, ".rs": true, ".java": true, ".kt": true, ".scala": true,
}

// minAppSourceFiles is how many compiled-language source files must accompany
// a build manifest before a repository counts as an application. Requiring
// real source — not just the manifest — closes an evasion path: an attacker
// cannot drop a 3-byte go.mod into a malicious skill bundle to suppress the
// skill-oriented scanners, because the source files would still be missing.
const minAppSourceFiles = 3

// IsApplicationRepo reports whether the repository is a compiled-language
// application. The skill-oriented scanners (capability drift, skillsafety
// exfil-intent correlation) analyse a skill's own files; running them across
// an application's source tree is a category error — the application's code
// is the implementation of a tool, not "the skill's scripts".
func IsApplicationRepo(files map[string][]byte) bool {
	hasManifest := false
	sourceCount := 0
	for p := range files {
		norm := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
		if appBuildManifests[path.Base(norm)] {
			hasManifest = true
		}
		if compiledSourceExts[path.Ext(norm)] {
			sourceCount++
		}
	}
	return hasManifest && sourceCount >= minAppSourceFiles
}

// ApplyFileRoles re-weights findings by the role of the file each was found
// in: test/rule-corpus findings are dropped, documentation findings are
// downgraded, code/config findings pass through. Findings with no File field
// are left untouched (the caller's scanner-level scoping handles those).
//
// For Markdown documents the line of the match is consulted: a match in prose
// (a sentence, a table cell) is dropped because prose only *describes* a
// pattern, while a match inside a code block is reduced to INFO because an
// example snippet is not the executable artifact.
func ApplyFileRoles(findings []Finding, files map[string][]byte) []Finding {
	kept := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.File == "" {
			kept = append(kept, f)
			continue
		}
		content := files[f.File]
		role := ClassifyFile(f.File, content)

		if role == RoleDoc && IsMarkdown(f.File) && f.Line > 0 {
			if !CodeBlockLines(content)[f.Line] {
				continue // prose match — described, not present
			}
			f.Severity = SevInfo // code-block example — informational only
			kept = append(kept, f)
			continue
		}

		sev, ok := AdjustSeverity(f.Severity, role)
		if !ok {
			continue
		}
		f.Severity = sev
		kept = append(kept, f)
	}
	return kept
}
