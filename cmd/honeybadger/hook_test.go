package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

	stub := "#!/bin/bash\necho 1 > \"$HB_MARKER\"\ncat \"$HB_VERDICT_FILE\"\nexit \"${HB_EXIT_CODE:-0}\"\n"
	verdicts := map[string]string{
		"PASS":      `{"type":"result","verdict":"PASS","reasoning":"clean"}`,
		"WARN":      `{"type":"result","verdict":"WARN","reasoning":"warning"}`,
		"FAIL":      `{"type":"result","verdict":"FAIL","reasoning":"secret found"}`,
		"MALFORMED": "this is not json {{{",
		"EMPTY":     ``,
		"PASS_WITH_SUMMARY": `{"type":"result","verdict":"PASS","reasoning":"clean"}
{"type":"suppression_summary","count":0}`,
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
				exitCode    int
				withStub    bool
				wantCode    int
				wantBlocked bool
				wantInvoked bool
				wantWarn    bool
			}{
				{"safe dir passes", "/skills/demo/SKILL.md", "PASS", 0, true, 0, false, true, false},
				{"fail blocks", "/skills/demo/SKILL.md", "FAIL", 2, true, 2, true, true, false},
				{"warn allowed", "/skills/demo/SKILL.md", "WARN", 1, true, 0, false, true, true},
				{"malformed blocks", "/skills/demo/SKILL.md", "MALFORMED", 3, true, 2, true, true, false},
				{"empty blocks", "/skills/demo/SKILL.md", "EMPTY", 3, true, 2, true, true, false},
				{"verdict status mismatch blocks", "/skills/demo/SKILL.md", "PASS", 2, true, 2, true, true, false},
				{"non-skill path skips", "/tmp/notes.txt", "", 0, true, 0, false, false, false},
				{"honeybadger missing", "/skills/demo/SKILL.md", "", 0, false, 0, false, false, true},
				{"result then summary passes", "/skills/demo/SKILL.md", "PASS_WITH_SUMMARY", 0, true, 0, false, true, false},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					os.Remove(marker)
					os.Remove(verdictFile)
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
						"HB_EXIT_CODE=" + strconv.Itoa(tc.exitCode),
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
