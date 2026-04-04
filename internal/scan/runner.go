package scan

import (
	"context"
	"fmt"
	"sync"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// ScanFunc is the signature all scanners implement.
type ScanFunc func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding)

// RunAll launches all applicable scanners concurrently based on paranoia level.
// Returns a channel that receives all findings from all scanners.
// The channel is closed when all scanners complete.
func RunAll(ctx context.Context, repo *fetch.Repo, opts Options) <-chan Finding {
	scanners := buildScannerList(opts)
	return RunAllWith(ctx, repo, opts, scanners)
}

// RunAllWith launches the given scanners concurrently and fans their findings
// into a single output channel. The channel is closed when all scanners complete.
func RunAllWith(ctx context.Context, repo *fetch.Repo, opts Options, scanners []ScanFunc) <-chan Finding {
	out := make(chan Finding, 50)

	var wg sync.WaitGroup
	for _, scan := range scanners {
		wg.Add(1)
		scan := scan // capture loop var
		go func() {
			defer wg.Done()
			// Each scanner gets its own channel and closes it
			ch := make(chan Finding, 50)

			// Fan-in goroutine: forward findings from scanner channel to main output
			var fanWg sync.WaitGroup
			fanWg.Add(1)
			go func() {
				defer fanWg.Done()
				for f := range ch {
					out <- f
				}
			}()

			// Run scanner synchronously so panic recovery works
			func() {
				defer func() {
					if r := recover(); r != nil {
						// ch is already closed by the scanner's defer close(out)
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

	// Close output channel when all scanners done
	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// buildScannerList returns the scanners to run based on paranoia level.
func buildScannerList(opts Options) []ScanFunc {
	switch opts.Paranoia {
	case ParanoiaOff:
		return nil
	case ParanoiaMinimal:
		return []ScanFunc{RunSecrets, RunCVE}
	case ParanoiaFamily:
		return []ScanFunc{RunSecrets, RunCVE, RunSupplyChain, RunMeta}
	case ParanoiaStrict:
		return []ScanFunc{RunSecrets, RunCVE, RunSupplyChain, RunMeta, RunAttestation}
	case ParanoiaParanoid:
		return []ScanFunc{RunSecrets, RunCVE, RunSupplyChain, RunMeta, RunAttestation}
	default:
		// Default to family
		return []ScanFunc{RunSecrets, RunCVE, RunSupplyChain, RunMeta}
	}
}
