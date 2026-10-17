package scan

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileRole classifies a repository file by what kind of artifact it is.
// Scanners and the verdict pipeline use the role to discriminate a threat
// that is *present* in executable code from one merely *described* in prose
// or a comment, or found in a file whose role is not yet distinguished.
//
// Findings are no longer dropped by role; instead the role is recorded on
// each Finding and used to adjust severity, giving the consumer full context.
type FileRole string

const (
	// RoleCode is real source: findings carry full severity.
	RoleCode FileRole = "code"
	// RoleProse is documentation/prose. A described pattern is far weaker
	// signal than a present one — findings are downgraded.
	RoleProse FileRole = "prose"
	// RoleComment is a comment line in source. The pattern is described, not
	// executed — findings are reduced to INFO.
	RoleComment FileRole = "comment"
	// RoleUnknown covers test fixtures, config, and rule-corpus files whose
	// role the classifier does not distinguish from ordinary code.
	RoleUnknown FileRole = "unknown"
)

// knownScanners are the scanner names a honeybadger rule YAML may target.
var knownScanners = map[string]bool{
	"supplychain": true, "skillsafety": true, "secrets": true,
	"capability": true, "cve": true, "meta": true,
	"mcptool": true, "attestation": true,
}

// CommentStyle is the per-file language family used for ambiguous line markers.
type CommentStyle uint8

const (
	Unknown CommentStyle = iota
	CFamily
	HashFamily
	DashFamily
	HTMLFamily
	PHPFamily
	SemicolonFamily
)

// extensionStyle is only a tiebreaker when content does not identify a style.
var extensionStyle = map[string]CommentStyle{
	".c": CFamily, ".h": CFamily, ".cc": CFamily, ".cpp": CFamily, ".hpp": CFamily,
	".java": CFamily, ".go": CFamily, ".rs": CFamily, ".swift": CFamily, ".scala": CFamily,
	".js": CFamily, ".jsx": CFamily, ".ts": CFamily, ".tsx": CFamily, ".css": CFamily,
	".sh": HashFamily, ".bash": HashFamily, ".zsh": HashFamily, ".fish": HashFamily,
	".py": HashFamily, ".rb": HashFamily, ".pl": HashFamily,
	".php": PHPFamily, ".lua": DashFamily, ".html": HTMLFamily,
	".bas": SemicolonFamily, ".asm": SemicolonFamily,
}

// sqlSelectFromPattern requires a SELECT ... FROM shape on one line.
var sqlSelectFromPattern = regexp.MustCompile(`(?i)\bselect\b[^\r\n;]*\bfrom\b`)

// ResolveStyle uses content signals first and the extension only as a final tie-break.
func ResolveStyle(content []byte, fileName string) CommentStyle {
	lines := bytes.Split(content, []byte{'\n'})
	if len(lines) > 0 {
		first := strings.TrimSpace(string(lines[0]))
		if strings.HasPrefix(first, "#!") {
			fields := strings.Fields(strings.TrimPrefix(first, "#!"))
			if len(fields) == 0 {
				return Unknown
			}
			interpreter := strings.ToLower(path.Base(fields[0]))
			if interpreter == "env" && len(fields) > 1 {
				interpreter = strings.ToLower(path.Base(fields[1]))
			}
			switch {
			case strings.Contains(interpreter, "sh"), strings.Contains(interpreter, "python"), strings.Contains(interpreter, "ruby"), strings.Contains(interpreter, "perl"), strings.Contains(interpreter, "awk"):
				return HashFamily
			case interpreter == "node" || interpreter == "deno" || interpreter == "bun":
				return CFamily
			default:
				return Unknown
			}
		}
	}
	probe := strings.ToLower(string(content))
	switch {
	case strings.Contains(probe, "<?php") || strings.Contains(probe, "<?="):
		return PHPFamily
	case strings.Contains(probe, "<?xml") || strings.Contains(probe, "<!doctype") || strings.Contains(probe, "<html"):
		return HTMLFamily
	case strings.Contains(probe, "#include") || strings.Contains(probe, "#define") || strings.Contains(probe, "#ifdef") || strings.Contains(probe, "#pragma"):
		return CFamily
	case strings.Contains(probe, ":=") || (strings.Contains(probe, "func ") && strings.Contains(probe, "package ")):
		return CFamily
	case strings.Contains(probe, "fn ") && strings.Contains(probe, "->") && !strings.Contains(probe, "func "):
		return CFamily
	case strings.Contains(probe, "local ") && strings.Contains(probe, "function ") && strings.Contains(probe, "end"):
		return DashFamily
	case sqlSelectFromPattern.MatchString(probe) || strings.Contains(probe, "create table"):
		return DashFamily
	case strings.Contains(probe, "def ") && strings.Contains(probe, "#"):
		return HashFamily
	}
	var hashes, slashes, dashes int
	for _, b := range lines {
		l := strings.TrimSpace(string(b))
		if strings.HasPrefix(l, "#") {
			hashes++
		}
		if strings.HasPrefix(l, "//") {
			slashes++
		}
		if strings.HasPrefix(l, "--") {
			dashes++
		}
	}
	if hashes > 1 && slashes == 0 {
		return HashFamily
	}
	if slashes > 0 && hashes == 0 && strings.ContainsAny(probe, "{}") {
		return CFamily
	}
	if dashes > 0 && hashes == 0 && slashes == 0 {
		return DashFamily
	}
	if hashes > 0 && slashes > 0 {
		return Unknown
	}
	if style, ok := extensionStyle[strings.ToLower(path.Ext(fileName))]; ok {
		return style
	}
	return Unknown
}

func openersFor(style CommentStyle) []string {
	switch style {
	case CFamily:
		return []string{"//"}
	case HashFamily:
		return []string{"#"}
	case DashFamily:
		return []string{"--"}
	case PHPFamily:
		return []string{"#", "//"}
	case SemicolonFamily:
		return []string{";"}
	default:
		return nil
	}
}

// IsCommentLine applies content-decisive markers before style-resolved markers.
func IsCommentLine(content []byte, lineNumber int, fileName string) bool {
	return isCommentLineWithStyle(content, lineNumber, ResolveStyle(content, fileName))
}

func isCommentLineWithStyle(content []byte, lineNumber int, style CommentStyle) bool {
	if lineNumber < 1 {
		return false
	}
	lines := bytes.Split(content, []byte{'\n'})
	if lineNumber > len(lines) {
		return false
	}
	line := bytes.TrimSpace(lines[lineNumber-1])
	if len(line) == 0 {
		return false
	}
	l := string(line)
	if lineNumber == 1 && strings.HasPrefix(l, "#!") {
		return true
	}
	if strings.HasPrefix(l, "<!--") {
		if end := strings.Index(l, "-->"); end >= 0 {
			return strings.TrimSpace(l[end+3:]) == ""
		}
		return true
	}
	if strings.HasPrefix(l, "/*") {
		if end := strings.Index(l, "*/"); end >= 0 {
			return strings.TrimSpace(l[end+2:]) == ""
		}
		return true
	}
	if l == "*/" || l == "-->" {
		return true
	}
	for _, opener := range openersFor(style) {
		if strings.HasPrefix(l, opener) {
			return true
		}
	}
	return false
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
// (relative, any OS separator) and, when available, its content.
//
// The new role set is {code, prose, comment, unknown}. Test fixtures,
// config, and rule-corpus files all map to RoleUnknown; the caller can
// distinguish them via the path if needed.
func ClassifyFile(rel string, content []byte) FileRole {
	p := strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	base := path.Base(p)
	ext := path.Ext(p)

	// Test material, config, and rule corpus → RoleUnknown.
	if isTestPath(p, base) {
		return RoleUnknown
	}
	if (ext == ".yaml" || ext == ".yml") && isRuleYAML(content) {
		return RoleUnknown
	}
	if configExts[ext] || strings.HasPrefix(base, "dockerfile") || hasSegment(p, ".github") {
		return RoleUnknown
	}
	// SKILL.md is the skill manifest — the subject of analysis, not prose.
	if base == "skill.md" {
		return RoleCode
	}
	if isDocPath(p, base, ext) {
		return RoleProse
	}
	return RoleCode
}

// IsFixtureFile reports whether rel is test material (test directories,
// _test.go, .test./spec. files, test_*.py). These files exercise or define
// attack patterns and are not live threats, so the skillsafety signal pass
// skips them even though ClassifyFile lumps them into RoleUnknown.
func IsFixtureFile(rel string) bool {
	p := strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	return isTestPath(p, path.Base(p))
}

// IsRuleYAMLFile reports whether the yaml/yml file at rel with the given
// content is a honeybadger detection rule — the rule corpus, which defines
// attack patterns rather than constituting them. It is excluded from the
// skillsafety signal pass for the same reason as test fixtures.
func IsRuleYAMLFile(rel string, content []byte) bool {
	p := strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	ext := path.Ext(p)
	return (ext == ".yaml" || ext == ".yml") && isRuleYAML(content)
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
// found in. Findings are no longer dropped; instead the role dictates how
// aggressively severity is downgraded.
func AdjustSeverity(raw string, role FileRole) string {
	switch role {
	case RoleProse:
		// A described threat is two severity levels weaker than a present one.
		rank := SeverityRank(raw) - 2
		if rank < 1 {
			return SevInfo
		}
		return severityForRank(rank)
	case RoleComment:
		return SevInfo
	default: // RoleCode, RoleUnknown
		return raw
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

// ApplyFileRoles annotates each finding with the FileRole of the file it was
// found in and adjusts severity accordingly. Findings are never dropped;
// the role and adjusted severity give the consumer full context.
//
// For Markdown documents the line of the match is consulted: a match in prose
// (a sentence, a table cell) is downgraded like other prose, while a match
// inside a code block is reduced to INFO because an example snippet is not
// the executable artifact. For source files, a match on a comment line is
// classified as RoleComment and reduced to INFO.
func ApplyFileRoles(findings []Finding, files map[string][]byte) []Finding {
	kept := make([]Finding, 0, len(findings))
	styleCache := make(map[string]CommentStyle)
	for i := range findings {
		f := &findings[i]
		if f.File == "" {
			f.FileRole = RoleUnknown
			kept = append(kept, *f)
			continue
		}
		content := files[f.File]
		role := ClassifyFile(f.File, content)

		// Markdown: distinguish code-block lines from prose.
		if role == RoleProse && IsMarkdown(f.File) && f.Line > 0 {
			if CodeBlockLines(content)[f.Line] {
				f.Severity = SevInfo
			} else {
				f.Severity = AdjustSeverity(f.Severity, RoleProse)
			}
			f.FileRole = RoleProse
			kept = append(kept, *f)
			continue
		}

		// Comment line in source code — described, not present.
		if role == RoleCode && f.Line > 0 {
			style, ok := styleCache[f.File]
			if !ok {
				style = ResolveStyle(content, f.File)
				styleCache[f.File] = style
			}
			if isCommentLineWithStyle(content, f.Line, style) {
				role = RoleComment
			}
		}

		f.FileRole = role
		f.Severity = AdjustSeverity(f.Severity, role)
		kept = append(kept, *f)
	}
	return kept
}
