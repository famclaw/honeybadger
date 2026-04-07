package supplychain

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
)

// isBinaryContent checks for null bytes in the first 512 bytes.
func isBinaryContent(data []byte) bool {
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// compiledPattern holds a compiled regex pattern from a YAML rule.
type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
	message  string
}

// dictRule holds a dictionary rule's metadata for typosquat matching.
type dictRule struct {
	Severity string
	Message  string
	Packages []string
}

// Run scans repository files for supply chain risk patterns.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	// Load patterns and dictionaries from rules (YAML-only, no hardcoded fallbacks).
	var activePatterns []compiledPattern
	var dictRules []dictRule

	rs, _ := opts.Rules.(*rules.RuleSet)
	for _, r := range rs.ByScanner("supplychain") {
		switch r.Kind {
		case "pattern":
			for _, cp := range r.CompiledPatterns() {
				activePatterns = append(activePatterns, compiledPattern{
					name:     r.ID,
					re:       cp.Re,
					severity: r.Severity,
					message:  r.Message,
				})
			}
		case "dictionary":
			dictRules = append(dictRules, dictRule{
				Severity: r.Severity,
				Message:  r.Message,
				Packages: r.Packages,
			})
		}
	}

	for path, content := range repo.Files {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if isBinaryContent(content) {
			continue
		}

		// Skip test files — regex patterns in tests are fixtures, not threats
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "testdata/") || strings.Contains(path, "testfixture/") {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, p := range activePatterns {
				if p.re.MatchString(line) {
					out <- scan.Finding{
						Type:     "finding",
						Severity: p.severity,
						Check:    "supplychain",
						File:     path,
						Line:     lineNum + 1,
						Message:  p.message,
						Snippet:  scan.Redact(strings.TrimSpace(line), 120),
					}
				}
			}
		}
	}

	// Typosquat detection using dictionary rules.
	checkTyposquatsWithDictRules(repo, out, dictRules)
}

// checkTyposquatsWithDictRules parses dependency names from package.json and requirements.txt
// and compares them against dictionary rule packages using edit distance.
// Each finding carries the rule's severity and message.
func checkTyposquatsWithDictRules(repo *fetch.Repo, out chan<- scan.Finding, dicts []dictRule) {
	depNames := extractDependencyNames(repo)
	for _, dep := range depNames {
		for _, dr := range dicts {
			for _, pkg := range dr.Packages {
				if dep == pkg {
					continue
				}
				dist := scan.EditDistance(dep, pkg)
				// Flag if edit distance is 1 or 2 (close but not identical)
				if dist > 0 && dist <= 2 {
					out <- scan.Finding{
						Type:     "finding",
						Severity: dr.Severity,
						Check:    "supplychain",
						Message:  fmt.Sprintf("%s: %q resembles %q (edit distance %d)", dr.Message, dep, pkg, dist),
						Package:  dep,
					}
				}
			}
		}
	}
}

// extractDependencyNames reads package.json and requirements.txt for dependency names.
func extractDependencyNames(repo *fetch.Repo) []string {
	var names []string

	// Parse package.json dependencies
	if content, ok := repo.Files["package.json"]; ok {
		names = append(names, parsePackageJSONDepNames(string(content))...)
	}

	// Parse requirements.txt
	if content, ok := repo.Files["requirements.txt"]; ok {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Split on ==, >=, <=, ~=, != etc
			for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">"} {
				if idx := strings.Index(line, sep); idx > 0 {
					line = line[:idx]
					break
				}
			}
			names = append(names, strings.TrimSpace(line))
		}
	}

	return names
}

// parsePackageJSONDepNames extracts dependency names from package.json content.
// Uses simple string parsing to avoid importing encoding/json here.
func parsePackageJSONDepNames(content string) []string {
	var names []string
	inDeps := false
	braceDepth := 0

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		// Check if we're entering a dependencies section
		if strings.Contains(trimmed, `"dependencies"`) ||
			strings.Contains(trimmed, `"devDependencies"`) ||
			strings.Contains(trimmed, `"peerDependencies"`) ||
			strings.Contains(trimmed, `"optionalDependencies"`) {
			inDeps = true
			braceDepth = 0
			if strings.Contains(trimmed, "{") {
				braceDepth++
			}
			continue
		}

		if inDeps {
			if strings.Contains(trimmed, "{") {
				braceDepth++
			}
			if strings.Contains(trimmed, "}") {
				braceDepth--
				if braceDepth <= 0 {
					inDeps = false
					continue
				}
			}

			// Extract package name: "name": "version"
			if idx := strings.Index(trimmed, `"`); idx >= 0 {
				rest := trimmed[idx+1:]
				if end := strings.Index(rest, `"`); end > 0 {
					name := rest[:end]
					if name != "" && !strings.Contains(name, ":") {
						names = append(names, name)
					}
				}
			}
		}
	}

	return names
}
