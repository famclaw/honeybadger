package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestScanSkillHooks execs each examples hook script against a PATH-shadowed
// stub honeybadger and asserts the documented exit-code contract.
func TestScanSkillHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook scripts require bash; Unix only")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq required by hook scripts")
	}

	stub := "#!/bin/bash\necho 1 > \"$HB_MARKER\"\ncat \"$HB_VERDICT_FILE\"\n"
	verdicts := map[string]string{
		"PASS": `{"verdict":"PASS","reasoning":"clean"}`,
		"WARN": `{"verdict":"WARN","reasoning":"warning"}`,
		"FAIL": `{"verdict":"FAIL","reasoning":"secret found"}`,
	}

	for _, dir := range []string{"examples/claude-code", "examples/codex-cli"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			binDir := filepath.Join(root, "bin")
			if err := os.MkdirAll(binDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(binDir, "honeybadger"), []byte(stub), 0755); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "invoked")
			verdictFile := filepath.Join(root, "verdict")
			hook := filepath.Join("..", "..", dir, "scan-skill.sh")

			cases := []struct {
				name        string
				filePath    string
				verdict     string
				withStub    bool
				wantCode    int
				wantBlocked bool
				wantInvoked bool
				wantWarn    bool
			}{
				{"safe dir passes", "/skills/demo/SKILL.md", "PASS", true, 0, false, true, false},
				{"fail blocks", "/skills/demo/SKILL.md", "FAIL", true, 2, true, true, false},
				{"warn passes", "/skills/demo/SKILL.md", "WARN", true, 0, false, true, false},
				{"non-skill path skips", "/tmp/notes.txt", "", true, 0, false, false, false},
				{"honeybadger missing", "/skills/demo/SKILL.md", "", false, 0, false, false, true},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					os.Remove(marker)
					if tc.verdict != "" {
						if err := os.WriteFile(verdictFile, []byte(verdicts[tc.verdict]), 0644); err != nil {
							t.Fatal(err)
						}
					}
					var pathVal string
					if tc.withStub {
						pathVal = binDir + string(os.PathListSeparator) + "/usr/bin:/bin"
					} else {
						pathVal = "/usr/bin:/bin"
					}
					cmd := exec.Command("bash", hook)
					cmd.Env = []string{
						"HB_MARKER=" + marker,
						"HB_VERDICT_FILE=" + verdictFile,
						"PATH=" + pathVal,
						"HOME=" + root,
					}
					cmd.Stdin = strings.NewReader(`{"file_path":"` + tc.filePath + `"}`)
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					code := 0
					if err := cmd.Run(); err != nil {
						if ee, ok := err.(*exec.ExitError); ok {
							code = ee.ExitCode()
						} else {
							t.Fatalf("hook failed to run: %v", err)
						}
					}
					if code != tc.wantCode {
						t.Errorf("exit = %d, want %d; stderr=%q", code, tc.wantCode, stderr.String())
					}
					gotBlocked := strings.Contains(stderr.String(), "BLOCKED")
					if gotBlocked != tc.wantBlocked {
						t.Errorf("stderr BLOCKED = %v, want %v; stderr=%q", gotBlocked, tc.wantBlocked, stderr.String())
					}
					_, invokedErr := os.Lstat(marker)
					gotInvoked := invokedErr == nil
					if gotInvoked != tc.wantInvoked {
						t.Errorf("stub invoked = %v, want %v", gotInvoked, tc.wantInvoked)
					}
					if tc.wantWarn && !strings.Contains(stderr.String(), "WARNING") {
						t.Errorf("stderr missing WARNING; got %q", stderr.String())
					}
				})
			}
		})
	}
}
