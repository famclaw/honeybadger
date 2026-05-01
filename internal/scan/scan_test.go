package scan

import (
	"context"
	"testing"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
)

func mockScanner(findings ...Finding) ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding, _ chan<- RuntimeError) {
		for _, f := range findings {
			select {
			case out <- f:
			case <-ctx.Done():
				return
			}
		}
	}
}

func panicScanner() ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding, _ chan<- RuntimeError) {
		panic("intentional test panic")
	}
}

func blockingScanner() ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding, _ chan<- RuntimeError) {
		<-ctx.Done()
	}
}

func dummyRepo() *fetch.Repo {
	return &fetch.Repo{
		URL:      "https://github.com/test/repo",
		Owner:    "test",
		Name:     "repo",
		Platform: "github",
	}
}

func TestRunAll_AllFindingsArrive(t *testing.T) {
	scanners := []ScanFunc{
		mockScanner(Finding{Check: "s1", Message: "a"}, Finding{Check: "s1", Message: "b"}),
		mockScanner(Finding{Check: "s2", Message: "c"}, Finding{Check: "s2", Message: "d"}),
		mockScanner(Finding{Check: "s3", Message: "e"}, Finding{Check: "s3", Message: "f"}),
	}

	ch := RunAll(context.Background(), dummyRepo(), Options{Paranoia: ParanoiaFamily}, scanners)
	var findings []Finding
	for ev := range ch {
		if f, ok := ev.(Finding); ok {
			findings = append(findings, f)
		}
	}
	if len(findings) != 6 {
		t.Errorf("expected 6 findings, got %d", len(findings))
	}
}

func TestRunAll_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := RunAll(ctx, dummyRepo(), Options{Paranoia: ParanoiaFamily}, []ScanFunc{blockingScanner()})
	cancel()

	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("output channel did not close after context cancellation")
	}
}

func TestRunAll_PanicRecovery(t *testing.T) {
	scanners := []ScanFunc{
		panicScanner(),
		mockScanner(Finding{Check: "good", Message: "normal finding"}),
	}

	ch := RunAll(context.Background(), dummyRepo(), Options{Paranoia: ParanoiaFamily}, scanners)
	var findings []Finding
	var runtimeErrors []RuntimeError
	for ev := range ch {
		switch v := ev.(type) {
		case Finding:
			findings = append(findings, v)
		case RuntimeError:
			runtimeErrors = append(runtimeErrors, v)
		}
	}

	var gotPanic bool
	for _, e := range runtimeErrors {
		if e.Scanner == "runner" {
			gotPanic = true
		}
	}
	if !gotPanic {
		t.Errorf("expected a RuntimeError from panic recovery, got %d errors", len(runtimeErrors))
	}

	var gotNormal bool
	for _, f := range findings {
		if f.Check == "good" {
			gotNormal = true
		}
	}
	if !gotNormal {
		t.Error("expected normal finding from non-panicking scanner")
	}
}

func TestRunAll_EmptyScannerList(t *testing.T) {
	ch := RunAll(context.Background(), dummyRepo(), Options{Paranoia: ParanoiaOff}, nil)
	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 events for empty scanner list, got %d", count)
	}
}
