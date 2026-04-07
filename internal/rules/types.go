package rules

import "regexp"

// Rule is a detection rule loaded from YAML.
type Rule struct {
	ID          string       `yaml:"id"`
	Kind        string       `yaml:"kind"`
	Scanner     string       `yaml:"scanner"`
	Category    string       `yaml:"category"`
	Severity    string       `yaml:"severity"`
	Signal      string       `yaml:"signal,omitempty"`
	Patterns    []PatternDef `yaml:"patterns,omitempty"`
	Packages    []string     `yaml:"packages,omitempty"`
	Message     string       `yaml:"message"`
	MoreInfoURL string       `yaml:"more_info_url,omitempty"`
	References  []string     `yaml:"references,omitempty"`
	compiled    []*CompiledPattern
}

// PatternDef is a regex pattern within a rule.
type PatternDef struct {
	Regex       string `yaml:"regex"`
	Description string `yaml:"description,omitempty"`
}

// CompiledPattern holds a compiled regex.
type CompiledPattern struct {
	Re          *regexp.Regexp
	Description string
}

// CompiledPatterns returns the compiled regexes for this rule.
func (r *Rule) CompiledPatterns() []*CompiledPattern {
	return r.compiled
}

// RuleSet is a loaded collection of rules.
type RuleSet struct {
	byScanner map[string][]*Rule
	all       []*Rule
}

// ByScanner returns rules for a given scanner name.
func (rs *RuleSet) ByScanner(scanner string) []*Rule {
	if rs == nil {
		return nil
	}
	return rs.byScanner[scanner]
}

// All returns every loaded rule.
func (rs *RuleSet) All() []*Rule {
	return rs.all
}
