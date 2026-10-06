//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/famclaw/honeybadger/internal/testfixture"
)

// TestCLI_SuppressionSummaryAfterResult is a regression test for the NDJSON
// event-ordering change in run(). The suppression_summary event must be emitted
// AFTER the result (verdict) event, matching the established stream order that
// positional NDJSON consumers rely on.
//
// Before the fix, the new trust-boundary policy work moved the suppression
// summary to be emitted before the findings and before the result event. That
// silently broke any consumer that reads the NDJSON stream positionally (or
// treats suppression_summary as a terminal marker). This test locks the order:
// suppression_summary must come after the first result event.
func TestCLI_SuppressionSummaryAfterResult(t *testing.T) {
	repo := testfixture.SecretsRepo()
	dir := testfixture.WriteToDir(t, repo)

	// Add a valid target .honeybadgerignore. With --trust-target-ignore,
	// Apply() records "target" in outcome.Applied even when it matches zero
	// findings, so a suppression_summary event is guaranteed to be emitted.
	ignoreContent := []byte("aws-access-key-token\n")
	if err := os.WriteFile(filepath.Join(dir, ".honeybadgerignore"), ignoreContent, 0644); err != nil {
		t.Fatalf("write .honeybadgerignore: %v", err)
	}

	cmd := exec.Command(testBinary, "scan", dir,
		"--paranoia", "family", "--format", "ndjson", "--offline", "--trust-target-ignore")
	out, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		t.Fatalf("binary did not start: %v\noutput: %s", err, out)
	}

	// Walk the NDJSON stream in order and record the line index of the first
	// result event and the last suppression_summary event.
	resultIdx := -1
	suppressionIdx := -1
	for i, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event map[string]any
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		switch event["type"] {
		case "result":
			if resultIdx == -1 {
				resultIdx = i
			}
		case "suppression_summary":
			suppressionIdx = i
		}
	}

	if resultIdx == -1 {
		t.Fatalf("no result event found in output:\n%s", out)
	}
	if suppressionIdx == -1 {
		t.Fatalf("no suppression_summary event found; a trusted target policy must emit one:\n%s", out)
	}
	if suppressionIdx < resultIdx {
		t.Errorf("suppression_summary at line index %d is emitted BEFORE result at line index %d; it must come after the result event", suppressionIdx, resultIdx)
	}
}
