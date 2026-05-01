package scan

import (
	"context"
	"fmt"
	"sync"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// ScanFunc is the signature all scanners implement.
//
// Findings (security issues) are sent on `out`. RuntimeErrors (scanner-internal
// failures: external service errors, config load errors, etc.) are sent on
// `errs`. Panics inside a ScanFunc are caught by RunAll and surfaced as a
// RuntimeError on `errs` automatically — scanners do not need to recover.
type ScanFunc func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding, errs chan<- RuntimeError)

// RunAll launches the given scanners concurrently.
// The scanner list is built by the caller (e.g. engine.BuildScannerList).
// Returns a single channel that multiplexes Findings and RuntimeErrors as Events.
// The channel is closed when all scanners complete.
func RunAll(ctx context.Context, repo *fetch.Repo, opts Options, scanners []ScanFunc) <-chan Event {
	out := make(chan Event, 50)

	var wg sync.WaitGroup
	for _, scan := range scanners {
		wg.Add(1)
		scan := scan // capture loop var
		go func() {
			defer wg.Done()
			findingsCh := make(chan Finding, 50)
			errsCh := make(chan RuntimeError, 4)

			var fanWg sync.WaitGroup
			fanWg.Add(2)
			go func() {
				defer fanWg.Done()
				for f := range findingsCh {
					out <- f
				}
			}()
			go func() {
				defer fanWg.Done()
				for e := range errsCh {
					out <- e
				}
			}()

			func() {
				defer close(findingsCh)
				defer close(errsCh)
				defer func() {
					if r := recover(); r != nil {
						errsCh <- NewRuntimeError("runner", fmt.Sprintf("scanner panicked: %v", r))
					}
				}()
				scan(ctx, repo, opts, findingsCh, errsCh)
			}()

			fanWg.Wait()
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
