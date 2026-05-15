package mcptool

import (
	"context"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// collect runs Run and gathers findings and runtime errors.
func collect(t *testing.T, repo *fetch.Repo, opts scan.Options) ([]scan.Finding, []scan.RuntimeError) {
	t.Helper()
	out := make(chan scan.Finding, 64)
	errs := make(chan scan.RuntimeError, 16)
	Run(context.Background(), repo, opts, out, errs)
	close(out)
	close(errs)
	var fs []scan.Finding
	for f := range out {
		fs = append(fs, f)
	}
	var es []scan.RuntimeError
	for e := range errs {
		es = append(es, e)
	}
	return fs, es
}

func TestRunNoMCPNoManifest(t *testing.T) {
	repo := &fetch.Repo{Files: mkFiles(map[string]string{"go.mod": "module x\n"})}
	fs, es := collect(t, repo, scan.Options{})
	if len(es) != 0 {
		t.Fatalf("unexpected runtime errors: %v", es)
	}
	if len(fs) != 0 {
		t.Fatalf("non-MCP repo with no manifest should yield no findings, got %v", fs)
	}
}
