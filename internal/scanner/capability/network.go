package capability

import (
	"regexp"
	"strings"
)

var (
	netURLRe   = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `\)]+|wss?://[^\s"']+`)
	netGoImpRe = regexp.MustCompile(`"net/http"|"net"|"net/url"`)
	netPyImpRe = regexp.MustCompile(`import\s+(requests|urllib|httpx|aiohttp)|from\s+urllib`)
	netJSRe    = regexp.MustCompile(`fetch\(|axios\.|new\s+XMLHttpRequest|WebSocket\(`)
	netShellRe = regexp.MustCompile(`(^|\||;|&&)\s*(curl|wget|nc)\s`)
)

func detectNetwork(files map[string][]byte) []evidence {
	var out []evidence
	for path, content := range files {
		if shouldSkipFile(path, content) {
			continue
		}
		text := string(content)
		if !netURLRe.MatchString(text) && !netGoImpRe.MatchString(text) &&
			!netPyImpRe.MatchString(text) && !netJSRe.MatchString(text) &&
			!netShellRe.MatchString(text) {
			continue
		}
		for i, line := range strings.Split(text, "\n") {
			if netURLRe.MatchString(line) || netGoImpRe.MatchString(line) ||
				netPyImpRe.MatchString(line) || netJSRe.MatchString(line) ||
				netShellRe.MatchString(line) {
				out = append(out, evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)})
			}
		}
	}
	return out
}
