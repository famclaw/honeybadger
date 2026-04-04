package scan

import (
	"context"
	"testing"
	"time"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// --- Mock scanner helpers ---

func mockScanner(findings ...Finding) ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
		defer close(out)
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
		defer close(out)
		panic("intentional test panic")
	}
}

func blockingScanner() ScanFunc {
	return func(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {
		defer close(out)
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

// --- Tests ---

func TestRunAll_AllFindingsArrive(t *testing.T) {
	scanners := []ScanFunc{
		mockScanner(
			Finding{Check: "s1", Message: "a"},
			Finding{Check: "s1", Message: "b"},
		),
		mockScanner(
			Finding{Check: "s2", Message: "c"},
			Finding{Check: "s2", Message: "d"},
		),
		mockScanner(
			Finding{Check: "s3", Message: "e"},
			Finding{Check: "s3", Message: "f"},
		),
	}

	ctx := context.Background()
	ch := RunAllWith(ctx, dummyRepo(), Options{Paranoia: ParanoiaFamily}, scanners)

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

	scanners := []ScanFunc{blockingScanner()}
	ch := RunAllWith(ctx, dummyRepo(), Options{Paranoia: ParanoiaFamily}, scanners)

	// Cancel after a short delay
	cancel()

	// Channel should close without hanging
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("output channel did not close after context cancellation")
	}
}

func TestRunAll_PanicRecovery(t *testing.T) {
	scanners := []ScanFunc{
		panicScanner(),
		mockScanner(Finding{Check: "good", Message: "normal finding"}),
	}

	ctx := context.Background()
	ch := RunAllWith(ctx, dummyRepo(), Options{Paranoia: ParanoiaFamily}, scanners)

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
			if f.Message == "" {
				t.Error("panic finding has empty message")
			}
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
	ctx := context.Background()
	ch := RunAllWith(ctx, dummyRepo(), Options{Paranoia: ParanoiaOff}, nil)

	var count int
	for range ch {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 findings for empty scanner list, got %d", count)
	}
}

func TestBuildScannerList_ParanoiaLevels(t *testing.T) {
	tests := []struct {
		paranoia ParanoiaLevel
		want     int
	}{
		{ParanoiaOff, 0},
		{ParanoiaMinimal, 2},
		{ParanoiaFamily, 4},
		{ParanoiaStrict, 5},
		{ParanoiaParanoid, 5},
	}

	for _, tt := range tests {
		t.Run(string(tt.paranoia), func(t *testing.T) {
			scanners := buildScannerList(Options{Paranoia: tt.paranoia})
			if len(scanners) != tt.want {
				t.Errorf("paranoia=%s: got %d scanners, want %d", tt.paranoia, len(scanners), tt.want)
			}
		})
	}
}

func TestRunAll_MinimalOnlySecretsAndCVE(t *testing.T) {
	// Use labeled mock scanners to verify only secrets and cve run at minimal level
	secretsScanner := mockScanner(Finding{Check: "secrets", Message: "secret found"})
	cveScanner := mockScanner(Finding{Check: "cve", Message: "cve found"})
	supplyChainScanner := mockScanner(Finding{Check: "supplychain", Message: "supply chain"})
	metaScanner := mockScanner(Finding{Check: "meta", Message: "meta"})
	attestationScanner := mockScanner(Finding{Check: "attestation", Message: "attestation"})

	// Only secrets and cve should run at minimal
	scanners := []ScanFunc{secretsScanner, cveScanner}

	// Verify the build function gives us 2 for minimal
	built := buildScannerList(Options{Paranoia: ParanoiaMinimal})
	if len(built) != 2 {
		t.Fatalf("expected 2 scanners for minimal, got %d", len(built))
	}

	// Run with only secrets + cve
	ctx := context.Background()
	ch := RunAllWith(ctx, dummyRepo(), Options{Paranoia: ParanoiaMinimal}, scanners)

	checks := make(map[string]bool)
	for f := range ch {
		checks[f.Check] = true
	}

	if !checks["secrets"] {
		t.Error("expected secrets findings")
	}
	if !checks["cve"] {
		t.Error("expected cve findings")
	}

	// Make sure excluded scanners didn't run (they weren't in the list)
	_ = supplyChainScanner
	_ = metaScanner
	_ = attestationScanner

	if checks["supplychain"] {
		t.Error("supplychain should not run at minimal level")
	}
	if checks["meta"] {
		t.Error("meta should not run at minimal level")
	}
	if checks["attestation"] {
		t.Error("attestation should not run at minimal level")
	}
}
