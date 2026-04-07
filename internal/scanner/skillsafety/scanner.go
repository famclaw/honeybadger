package skillsafety

import (
	"context"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// Run implements scan.ScanFunc for the skillsafety scanner.
// It extracts structured signals from the repository's skill files,
// evaluates them against safety rules, and emits findings.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding) {
	signals := Extract(repo)
	findings := Evaluate(&signals)
	for _, f := range findings {
		select {
		case <-ctx.Done():
			return
		case out <- f:
		}
	}
}
