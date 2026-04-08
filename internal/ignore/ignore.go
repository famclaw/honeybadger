package ignore

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/famclaw/honeybadger/internal/scan"
)

// Rule is a single suppression rule.
type Rule struct {
	RuleID   string
	PathGlob string
	SHA256   string
	Source   string // e.g. ".honeybadgerignore:12"
}

// Set is a parsed collection of suppression rules.
type Set struct {
	rules []Rule
}

// SuppressedFinding records a finding that was suppressed.
type SuppressedFinding struct {
	Finding   scan.Finding
	MatchedBy Rule
}

// Parse reads .honeybadgerignore content.
func Parse(content []byte, source string) (*Set, error) {
	s := &Set{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) > 2 {
			return nil, fmt.Errorf("%s:%d: too many tokens (expected RULE_ID [GLOB|sha256:HASH])", source, lineNum)
		}
		rule := Rule{
			RuleID: tokens[0],
			Source: fmt.Sprintf("%s:%d", source, lineNum),
		}
		if len(tokens) == 2 {
			constraint := tokens[1]
			if strings.HasPrefix(constraint, "sha256:") {
				rule.SHA256 = strings.TrimPrefix(constraint, "sha256:")
			} else {
				rule.PathGlob = constraint
			}
		}
		s.rules = append(s.rules, rule)
	}
	return s, nil
}

// Match returns the first Rule that matches the finding, or nil.
func (s *Set) Match(f *scan.Finding) *Rule {
	if s == nil || f.RuleID == "" {
		return nil
	}
	for i := range s.rules {
		r := &s.rules[i]
		if r.RuleID != f.RuleID {
			continue
		}
		if r.PathGlob != "" {
			matched, err := filepath.Match(r.PathGlob, f.File)
			if err != nil || !matched {
				continue
			}
		}
		if r.SHA256 != "" {
			if f.Snippet == "" {
				continue
			}
			hash := sha256.Sum256([]byte(f.Snippet))
			if fmt.Sprintf("%x", hash) != r.SHA256 {
				continue
			}
		}
		return r
	}
	return nil
}

// Filter returns kept findings and suppressed findings.
func (s *Set) Filter(findings []scan.Finding) ([]scan.Finding, []SuppressedFinding) {
	if s == nil || len(s.rules) == 0 {
		return findings, nil
	}
	var kept []scan.Finding
	var suppressed []SuppressedFinding
	for _, f := range findings {
		if r := s.Match(&f); r != nil {
			suppressed = append(suppressed, SuppressedFinding{Finding: f, MatchedBy: *r})
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}
