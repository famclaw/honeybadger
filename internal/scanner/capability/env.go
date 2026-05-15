package capability

import (
	"regexp"
	"strings"
)

var (
	envGoRe    = regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("([A-Z_][A-Z0-9_]*)"`)
	envPyRe    = regexp.MustCompile(`os\.environ(?:\[|\.get\(|\s*\.\s*get\()"([A-Z_][A-Z0-9_]*)"|os\.getenv\("([A-Z_][A-Z0-9_]*)"`)
	envJSRe    = regexp.MustCompile(`process\.env\.([A-Z_][A-Z0-9_]*)|process\.env\["([A-Z_][A-Z0-9_]*)"\]`)
	envShellRe = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)\}|\$([A-Z_][A-Z0-9_]*)\b`)
)

func detectEnv(files map[string][]byte) []envEvidence {
	var out []envEvidence
	for path, content := range files {
		if shouldSkipFile(path, content) {
			continue
		}
		text := string(content)
		for i, line := range strings.Split(text, "\n") {
			collect := func(matches [][]string) {
				for _, m := range matches {
					for j := 1; j < len(m); j++ {
						if m[j] != "" {
							out = append(out, envEvidence{evidence: evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)}, Var: m[j]})
							break
						}
					}
				}
			}
			collect(envGoRe.FindAllStringSubmatch(line, -1))
			collect(envPyRe.FindAllStringSubmatch(line, -1))
			collect(envJSRe.FindAllStringSubmatch(line, -1))
			collect(envShellRe.FindAllStringSubmatch(line, -1))
		}
	}
	return out
}
