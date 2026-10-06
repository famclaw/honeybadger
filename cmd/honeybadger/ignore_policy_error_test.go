package main

import (
	"errors"
	"strings"
	"testing"
)

// TestIgnorePolicyLoadError pins the operator-facing error message for a failed
// ignore-policy load. This guards the "clearer error message distinguishing
// operator policy file from target ignore file" review finding so a regression
// does not collapse it back into a generic "loading ignore policy" error.
//
// The message must:
//  1. name the operator policy file via --ignore-file,
//  2. state that it is trusted operator input that must parse,
//  3. distinguish it from the target's own .honeybadgerignore (untrusted by
//     default, which only warns),
//  4. preserve the underlying parse detail (file + line + token rule), and
//  5. keep the error chain so errors.Is/As still reach the root cause.
func TestIgnorePolicyLoadError(t *testing.T) {
	opPath := "/tmp/operator-policy.honeybadgerignore"
	underlying := errors.New(`/tmp/operator-policy.honeybadgerignore:3: too many tokens (expected RULE_ID [GLOB|sha256:HASH])`)

	err := ignorePolicyLoadError(opPath, underlying)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	msg := err.Error()

	for _, want := range []string{
		`--ignore-file "/tmp/operator-policy.honeybadgerignore"`,
		"trusted operator input",
		"must parse",
		".honeybadgerignore is a separate, untrusted-by-default source",
		"only produces a warning",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("operator policy error message missing %q; got: %s", want, msg)
		}
	}

	// The underlying parse detail (token rule) must be preserved verbatim.
	if !strings.Contains(msg, "too many tokens") {
		t.Errorf("expected underlying parse detail to be preserved; got: %s", msg)
	}

	// The operator-file error must NOT reuse the target-parse warning wording,
	// confirming the two failure modes stay visually distinct.
	if strings.Contains(msg, "continuing without target suppressions") {
		t.Errorf("operator error must not reuse the target-warning wording; got: %s", msg)
	}

	// The error chain is preserved for errors.Is/As consumers.
	if !errors.Is(err, underlying) {
		t.Errorf("expected errors.Is to match the underlying parse error; got: %s", msg)
	}
}
