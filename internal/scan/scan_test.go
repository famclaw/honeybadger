package scan

import (
	"context"
	"testing"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
)

func mockScanner(findings ...Finding) ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
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
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
		panic("intentional test panic")
	}
}

func blockingScanner() ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
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
	for f := range ch {
		findings = append(findings, f)
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
	for f := range ch {
		findings = append(findings, f)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (1 error + 1 normal), got %d", len(findings))
	}

	var gotPanic, gotNormal bool
	for _, f := range findings {
		if f.Severity == SevError && f.Check == "runner" {
			gotPanic = true
		}
		if f.Check == "good" {
			gotNormal = true
		}
	}
	if !gotPanic {
		t.Error("expected an ERROR finding from panic recovery")
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
		t.Errorf("expected 0 findings for empty scanner list, got %d", count)
	}
}
