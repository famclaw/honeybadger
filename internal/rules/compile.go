package rules

import (
	"fmt"
	"regexp"
)

var validSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
}

var validKinds = map[string]bool{
	"pattern": true, "dictionary": true,
}

func validateRule(r *Rule) error {
	if r.ID == "" {
		return fmt.Errorf("missing id")
	}
	if !validKinds[r.Kind] {
		return fmt.Errorf("invalid kind %q", r.Kind)
	}
	if r.Scanner == "" {
		return fmt.Errorf("missing scanner")
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Message == "" {
		return fmt.Errorf("missing message")
	}
	return nil
}

func compileRule(r *Rule) error {
	if r.Kind != "pattern" {
		return nil
	}
	r.compiled = make([]*CompiledPattern, 0, len(r.Patterns))
	for _, p := range r.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return fmt.Errorf("pattern %q: %w", p.Regex, err)
		}
		r.compiled = append(r.compiled, &CompiledPattern{Re: re, Description: p.Description})
	}
	return nil
}
