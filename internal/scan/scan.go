package scan

import (
	"context"
	"fmt"
	"sync"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// ScanFunc is the signature all scanners implement.
type ScanFunc func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding)

// RunAll launches the given scanners concurrently.
// The scanner list is built by the caller (e.g. engine.BuildScannerList).
// Returns a channel that receives all findings from all scanners.
// The channel is closed when all scanners complete.
func RunAll(ctx context.Context, repo *fetch.Repo, opts Options, scanners []ScanFunc) <-chan Finding {
	out := make(chan Finding, 50)

	var wg sync.WaitGroup
	for _, scan := range scanners {
		wg.Add(1)
		scan := scan // capture loop var
		go func() {
			defer wg.Done()
			ch := make(chan Finding, 50)

			var fanWg sync.WaitGroup
			fanWg.Add(1)
			go func() {
				defer fanWg.Done()
				for f := range ch {
					out <- f
				}
			}()

			func() {
				defer close(ch)
				defer func() {
					if r := recover(); r != nil {
						out <- Finding{
							Type:     "finding",
							Severity: SevError,
							Check:    "runner",
							Message:  fmt.Sprintf("scanner panicked: %v", r),
						}
					}
				}()
				scan(ctx, repo, opts, ch)
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
