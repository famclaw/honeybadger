package scan

import (
	"context"
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
)

var supplyChainPatterns = []struct {
	name     string
	regex    string
	severity string
	message  string
}{
	{"curl_pipe_bash", `curl[^|]+\|\s*(ba)?sh`, "HIGH", "Downloads and executes remote script via curl"},
	{"wget_pipe_bash", `wget[^-][^|]+\|\s*(ba)?sh`, "HIGH", "Downloads and executes remote script via wget"},
	{"eval_remote_fetch", `eval\s*\(\s*(fetch|require|import)\s*\(`, "HIGH", "Evaluates remotely fetched code"},
	{"remote_exec", `exec\s*\(\s*["']https?://`, "HIGH", "Executes code from remote URL"},
	{"shell_profile_write", `(>>|>)\s*~?\/?\.?(bashrc|zshrc|profile|bash_profile)`, "HIGH", "Modifies shell startup files"},
	{"postinstall_hook", `"postinstall"\s*:\s*"[^"]+"`, "MEDIUM", "package.json postinstall hook present"},
	{"path_traversal", `\.\./\.\./\.\./`, "MEDIUM", "Path traversal pattern detected"},
	{"etc_access", `\/etc\/(passwd|shadow|sudoers|hosts)`, "HIGH", "Reads sensitive system files"},
	{"ssh_dir_access", `~/\.ssh\/|\/\.ssh\/`, "HIGH", "Accesses SSH directory"},
	{"home_dir_glob", `glob\s*\(\s*["']~\/\*`, "MEDIUM", "Globs home directory"},
	{"dynamic_require", `require\s*\(\s*[^"']`, "LOW", "Dynamic require/import (variable path)"},
	{"base64_eval", `eval\s*\(\s*(atob|Buffer\.from|base64)`, "HIGH", "Evaluates base64-decoded content"},
	// Network risk patterns
	{"reverse_shell", `(?i)(?:nc|ncat|netcat)\s+-[el]|bash\s+-i\s+>&|/dev/tcp/`, "CRITICAL", "Reverse shell pattern detected"},
	{"crypto_mining", `(?i)(?:coinhive|cryptonight|stratum\+tcp|xmrig)`, "CRITICAL", "Crypto mining code detected"},
	{"webhook_exfil", `(?i)(?:fetch|axios|got|request)\s*\(\s*['"]https?://(?:webhook\.site|requestbin|pipedream|hookbin)`, "CRITICAL", "Data exfiltration via webhook inspection service"},
	{"hardcoded_ip", `https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/`, "HIGH", "Hardcoded IP endpoint"},
}

var compiledPatterns []struct {
	name     string
	re       *regexp.Regexp
	severity string
	message  string
}

func init() {
	compiledPatterns = make([]struct {
		name     string
		re       *regexp.Regexp
		severity string
		message  string
	}, len(supplyChainPatterns))
	for i, p := range supplyChainPatterns {
		compiledPatterns[i] = struct {
			name     string
			re       *regexp.Regexp
			severity string
			message  string
		}{
			name:     p.name,
			re:       regexp.MustCompile(p.regex),
			severity: p.severity,
			message:  p.message,
		}
	}
}

var popularPackages = []string{
	"react", "express", "lodash", "axios", "webpack", "typescript", "eslint",
	"jest", "chalk", "commander", "yargs", "dotenv", "moment", "uuid",
	"@anthropic-ai/sdk", "@modelcontextprotocol/sdk", "openai", "mcp",
	"requests", "flask", "django", "numpy", "pandas", "pydantic", "fastapi",
}

// isBinaryContent checks for null bytes in the first 512 bytes.
func isBinaryContent(data []byte) bool {
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// RunSupplyChain scans repository files for supply chain risk patterns.
func RunSupplyChain(ctx context.Context, repo *fetch.Repo, opts Options, out chan<- Finding) {

	for path, content := range repo.Files {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if isBinaryContent(content) {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			for _, p := range compiledPatterns {
				if p.re.MatchString(line) {
					out <- Finding{
						Type:     "finding",
						Severity: p.severity,
						Check:    "supplychain",
						File:     path,
						Line:     lineNum + 1,
						Message:  p.message,
						Snippet:  Redact(strings.TrimSpace(line), 120),
					}
				}
			}
		}
	}

	// Typosquat detection
	checkTyposquats(repo, out)
}

// checkTyposquats parses dependency names from package.json and requirements.txt
// and compares them against popular packages using edit distance.
func checkTyposquats(repo *fetch.Repo, out chan<- Finding) {
	depNames := extractDependencyNames(repo)
	for _, dep := range depNames {
		for _, popular := range popularPackages {
			if dep == popular {
				continue
			}
			dist := EditDistance(dep, popular)
			// Flag if edit distance is 1 or 2 (close but not identical)
			if dist > 0 && dist <= 2 {
				out <- Finding{
					Type:     "finding",
					Severity: SevHigh,
					Check:    "supplychain",
					Message:  "Possible typosquat: \"" + dep + "\" is close to popular package \"" + popular + "\"",
					Package:  dep,
				}
			}
		}
	}
}

// extractDependencyNames reads package.json and requirements.txt for dependency names.
func extractDependencyNames(repo *fetch.Repo) []string {
	var names []string

	// Parse package.json dependencies
	if content, ok := repo.Files["package.json"]; ok {
		names = append(names, parsePackageJSONDepNames(string(content))...)
	}

	// Parse requirements.txt
	if content, ok := repo.Files["requirements.txt"]; ok {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Split on ==, >=, <=, ~=, != etc
			for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">"} {
				if idx := strings.Index(line, sep); idx > 0 {
					line = line[:idx]
					break
				}
			}
			names = append(names, strings.TrimSpace(line))
		}
	}

	return names
}

// parsePackageJSONDepNames extracts dependency names from package.json content.
// Uses simple string parsing to avoid importing encoding/json here.
func parsePackageJSONDepNames(content string) []string {
	var names []string
	inDeps := false
	braceDepth := 0

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		// Check if we're entering a dependencies section
		if strings.Contains(trimmed, `"dependencies"`) ||
			strings.Contains(trimmed, `"devDependencies"`) ||
			strings.Contains(trimmed, `"peerDependencies"`) ||
			strings.Contains(trimmed, `"optionalDependencies"`) {
			inDeps = true
			braceDepth = 0
			if strings.Contains(trimmed, "{") {
				braceDepth++
			}
			continue
		}

		if inDeps {
			if strings.Contains(trimmed, "{") {
				braceDepth++
			}
			if strings.Contains(trimmed, "}") {
				braceDepth--
				if braceDepth <= 0 {
					inDeps = false
					continue
				}
			}

			// Extract package name: "name": "version"
			if idx := strings.Index(trimmed, `"`); idx >= 0 {
				rest := trimmed[idx+1:]
				if end := strings.Index(rest, `"`); end > 0 {
					name := rest[:end]
					if name != "" && !strings.Contains(name, ":") {
						names = append(names, name)
					}
				}
			}
		}
	}

	return names
}
