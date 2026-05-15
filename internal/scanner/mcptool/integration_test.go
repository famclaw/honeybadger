package mcptool

import (
	"testing"

	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/testfixture"
)

func TestIntegrationPoisonedSource(t *testing.T) {
	repo := testfixture.PoisonedMCPSourceRepo()
	fs, es := collect(t, repo, scan.Options{Rules: mustRules(t)})
	if len(es) != 0 {
		t.Fatalf("runtime errors: %v", es)
	}
	if hasRule(fs, "mcp-concealment") == nil {
		t.Fatalf("concealment not detected in poisoned source repo: %+v", fs)
	}
	if hasRule(fs, "mcp-source-only") == nil {
		t.Fatalf("source-only mode note missing: %+v", fs)
	}
}

func TestIntegrationDynamicRepoNoTools(t *testing.T) {
	repo := testfixture.DynamicMCPRepo()
	fs, es := collect(t, repo, scan.Options{Rules: mustRules(t)})
	if len(es) != 0 {
		t.Fatalf("runtime errors: %v", es)
	}
	if hasRule(fs, "mcp-no-tools-found") == nil {
		t.Fatalf("mcp-no-tools-found not emitted for dynamic MCP repo: %+v", fs)
	}
}

func TestIntegrationCleanRepoNoFindings(t *testing.T) {
	fs, es := collect(t, testfixture.CleanRepo(), scan.Options{Rules: mustRules(t)})
	if len(es) != 0 || len(fs) != 0 {
		t.Fatalf("clean non-MCP repo produced output: findings=%v errs=%v", fs, es)
	}
}
