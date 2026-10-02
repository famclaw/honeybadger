package ignore

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
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

// Outcome represents the results of applying a policy to findings.
type Outcome struct {
	// Effective findings after suppression
	Effective []scan.Finding

	// Suppressed findings
	Suppressed []SuppressedFinding

	// Applied suppression sources (e.g., "target", "operator")
	Applied []string

	// Ignored suppression sources (e.g., "target", "operator")
	Ignored []string
}

// Policy represents a combined suppression policy.
type Policy struct {
	// Target ignore rules (from .honeybadgerignore in target repo)
	Target *Set

	// Operator ignore rules (from operator-supplied policy)
	Operator *Set

	// Whether to trust target ignore rules
	TrustTarget bool
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
				hash := strings.TrimPrefix(constraint, "sha256:")
				if hash == "" {
					return nil, fmt.Errorf("%s:%d: empty sha256 hash", source, lineNum)
				}
				rule.SHA256 = hash
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

// LoadPolicy loads a suppression policy from target directory and operator policy file.
func LoadPolicy(targetDir, operatorPolicyFile string, trustTarget bool) (*Policy, error) {
	p := &Policy{
		TrustTarget: trustTarget,
	}

	// Load target ignore rules from .honeybadgerignore in target directory
	targetIgnorePath := filepath.Join(targetDir, ".honeybadgerignore")
	if _, err := os.Stat(targetIgnorePath); err == nil {
		content, err := os.ReadFile(targetIgnorePath)
		if err != nil {
			return nil, fmt.Errorf("reading target ignore file: %w", err)
		}
		p.Target, err = Parse(content, ".honeybadgerignore")
		if err != nil {
			return nil, fmt.Errorf("parsing target ignore file: %w", err)
		}
	}

	// Load operator ignore rules from operator policy file if provided
	if operatorPolicyFile != "" {
		content, err := os.ReadFile(operatorPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("reading operator policy file: %w", err)
		}
		p.Operator, err = Parse(content, operatorPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("parsing operator policy file: %w", err)
		}
	}

	return p, nil
}

// LoadPolicyFromContent loads a suppression policy using explicit content from repo files.
// This allows passing the actual content from repo.Files instead of reading from filesystem.
func LoadPolicyFromContent(targetContent []byte, operatorPolicyFile string, trustTarget bool) (*Policy, error) {
	p := &Policy{
		TrustTarget: trustTarget,
	}

	// Load target ignore rules from provided content
	if len(targetContent) > 0 {
		set, parseErr := Parse(targetContent, ".honeybadgerignore")
		if parseErr != nil {
			p.Target = nil
		} else {
			p.Target = set
		}
	}

	// Load operator ignore rules from operator policy file if provided
	if operatorPolicyFile != "" {
		content, err := os.ReadFile(operatorPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("reading operator policy file: %w", err)
		}
		p.Operator, err = Parse(content, operatorPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("parsing operator policy file: %w", err)
		}
	}

	return p, nil
}

// Apply applies a suppression policy to findings.
func Apply(policy *Policy, findings []scan.Finding) *Outcome {
	outcome := &Outcome{
		Effective:  make([]scan.Finding, 0),
		Suppressed: make([]SuppressedFinding, 0),
		Applied:    make([]string, 0),
		Ignored:    make([]string, 0),
	}

	// Track which findings are suppressed
	var suppressedFindings []SuppressedFinding
	keptFindings := make([]scan.Finding, 0)

	// Apply target ignore rules only if trust is enabled
	if policy.TrustTarget && policy.Target != nil {
		kept, suppressed := policy.Target.Filter(findings)
		keptFindings = kept
		suppressedFindings = append(suppressedFindings, suppressed...)
		outcome.Applied = append(outcome.Applied, "target")
	} else if policy.Target != nil {
		// If target is not trusted, we don't apply target rules, so all findings stay
		keptFindings = findings
		outcome.Ignored = append(outcome.Ignored, "target")
	} else {
		keptFindings = findings
	}

	// Apply operator rules if present
	if policy.Operator != nil {
		kept, suppressed := policy.Operator.Filter(keptFindings)
		keptFindings = kept
		suppressedFindings = append(suppressedFindings, suppressed...)
		outcome.Applied = append(outcome.Applied, "operator")
	}

	// Set the final results
	outcome.Effective = keptFindings
	outcome.Suppressed = suppressedFindings

	return outcome
}
