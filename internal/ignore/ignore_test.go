package ignore

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantRules int
		wantErr   bool
	}{
		{
			name:      "bare rule ID",
			content:   "SECRET_IN_CODE\n",
			wantRules: 1,
		},
		{
			name:      "rule with glob",
			content:   "SECRET_IN_CODE *.go\n",
			wantRules: 1,
		},
		{
			name:      "rule with sha256",
			content:   "SECRET_IN_CODE sha256:abc123\n",
			wantRules: 1,
		},
		{
			name:      "comments and blank lines",
			content:   "# comment\n\nSECRET_IN_CODE\n\n# another\n",
			wantRules: 1,
		},
		{
			name:      "multiple rules",
			content:   "RULE_A\nRULE_B *.py\nRULE_C sha256:deadbeef\n",
			wantRules: 3,
		},
		{
			name:    "too many tokens",
			content: "RULE_A *.go extra_token\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := Parse([]byte(tt.content), ".honeybadgerignore")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(set.rules) != tt.wantRules {
				t.Errorf("got %d rules, want %d", len(set.rules), tt.wantRules)
			}
		})
	}
}

func TestParseRuleFields(t *testing.T) {
	content := "RULE_A\nRULE_B *.go\nRULE_C sha256:abc123\n"
	set, err := Parse([]byte(content), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if set.rules[0].RuleID != "RULE_A" || set.rules[0].PathGlob != "" || set.rules[0].SHA256 != "" {
		t.Errorf("rule 0: %+v", set.rules[0])
	}
	if set.rules[1].RuleID != "RULE_B" || set.rules[1].PathGlob != "*.go" {
		t.Errorf("rule 1: %+v", set.rules[1])
	}
	if set.rules[2].RuleID != "RULE_C" || set.rules[2].SHA256 != "abc123" {
		t.Errorf("rule 2: %+v", set.rules[2])
	}

	// Check source annotation
	if set.rules[0].Source != "test:1" {
		t.Errorf("rule 0 source = %q, want %q", set.rules[0].Source, "test:1")
	}
}

func TestMatch(t *testing.T) {
	snippetHash := sha256.Sum256([]byte("mysecret"))
	snippetHashStr := fmt.Sprintf("%x", snippetHash)

	tests := []struct {
		name    string
		rules   string
		finding scan.Finding
		want    bool
	}{
		{
			name:  "bare ID matches any file",
			rules: "SECRET_LEAK\n",
			finding: scan.Finding{
				RuleID: "SECRET_LEAK",
				File:   "config.yaml",
			},
			want: true,
		},
		{
			name:  "glob matches",
			rules: "SECRET_LEAK *.yaml\n",
			finding: scan.Finding{
				RuleID: "SECRET_LEAK",
				File:   "config.yaml",
			},
			want: true,
		},
		{
			name:  "glob does not match",
			rules: "SECRET_LEAK *.go\n",
			finding: scan.Finding{
				RuleID: "SECRET_LEAK",
				File:   "config.yaml",
			},
			want: false,
		},
		{
			name:  "sha256 matches",
			rules: "SECRET_LEAK sha256:" + snippetHashStr + "\n",
			finding: scan.Finding{
				RuleID:  "SECRET_LEAK",
				Snippet: "mysecret",
			},
			want: true,
		},
		{
			name:  "sha256 does not match",
			rules: "SECRET_LEAK sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
			finding: scan.Finding{
				RuleID:  "SECRET_LEAK",
				Snippet: "mysecret",
			},
			want: false,
		},
		{
			name:  "different rule ID",
			rules: "OTHER_RULE\n",
			finding: scan.Finding{
				RuleID: "SECRET_LEAK",
				File:   "config.yaml",
			},
			want: false,
		},
		{
			name:  "empty RuleID never matches",
			rules: "SECRET_LEAK\n",
			finding: scan.Finding{
				RuleID: "",
				File:   "config.yaml",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := Parse([]byte(tt.rules), "test")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			got := set.Match(&tt.finding)
			if tt.want && got == nil {
				t.Error("expected match, got nil")
			}
			if !tt.want && got != nil {
				t.Errorf("expected no match, got %+v", got)
			}
		})
	}
}

func TestMatchNilSet(t *testing.T) {
	var s *Set
	f := &scan.Finding{RuleID: "RULE_A"}
	if r := s.Match(f); r != nil {
		t.Error("nil set should return nil")
	}
}

func TestFilter(t *testing.T) {
	rules := "RULE_A\nRULE_B *.py\n"
	set, err := Parse([]byte(rules), "test")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	findings := []scan.Finding{
		{RuleID: "RULE_A", File: "a.go", Message: "first"},
		{RuleID: "RULE_C", File: "b.go", Message: "second"},
		{RuleID: "RULE_B", File: "c.py", Message: "third"},
		{RuleID: "RULE_B", File: "d.go", Message: "fourth"},
	}

	kept, suppressed := set.Filter(findings)

	if len(kept) != 2 {
		t.Errorf("kept %d findings, want 2", len(kept))
	}
	if len(suppressed) != 2 {
		t.Errorf("suppressed %d findings, want 2", len(suppressed))
	}

	// Check order preserved
	if kept[0].Message != "second" {
		t.Errorf("kept[0].Message = %q, want %q", kept[0].Message, "second")
	}
	if kept[1].Message != "fourth" {
		t.Errorf("kept[1].Message = %q, want %q", kept[1].Message, "fourth")
	}

	// Check suppressed carries the rule
	if suppressed[0].MatchedBy.RuleID != "RULE_A" {
		t.Errorf("suppressed[0] matched by %q, want %q", suppressed[0].MatchedBy.RuleID, "RULE_A")
	}
	if suppressed[1].MatchedBy.RuleID != "RULE_B" {
		t.Errorf("suppressed[1] matched by %q, want %q", suppressed[1].MatchedBy.RuleID, "RULE_B")
	}
}

func TestFilterEmptySet(t *testing.T) {
	set, err := Parse([]byte(""), "test")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	findings := []scan.Finding{
		{RuleID: "RULE_A", Message: "first"},
	}

	kept, suppressed := set.Filter(findings)
	if len(kept) != 1 {
		t.Errorf("kept %d, want 1", len(kept))
	}
	if len(suppressed) != 0 {
		t.Errorf("suppressed %d, want 0", len(suppressed))
	}
}

func TestFilterNilSet(t *testing.T) {
	var set *Set
	findings := []scan.Finding{
		{RuleID: "RULE_A", Message: "first"},
	}

	kept, suppressed := set.Filter(findings)
	if len(kept) != 1 {
		t.Errorf("kept %d, want 1", len(kept))
	}
	if suppressed != nil {
		t.Errorf("suppressed = %v, want nil", suppressed)
	}
}

func TestParseSource(t *testing.T) {
	content := "# comment\nRULE_A\n\nRULE_B *.go\n"
	set, err := Parse([]byte(content), ".honeybadgerignore")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !strings.HasSuffix(set.rules[0].Source, ":2") {
		t.Errorf("rule 0 source = %q, want suffix :2", set.rules[0].Source)
	}
	if !strings.HasSuffix(set.rules[1].Source, ":4") {
		t.Errorf("rule 1 source = %q, want suffix :4", set.rules[1].Source)
	}
}
