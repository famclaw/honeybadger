package capability

import (
	"regexp"
	"strings"
)

var (
	fsUnixPathRe = regexp.MustCompile(`/etc/|/var/|/usr/|/home/|/opt/|/root/`)
	fsWinPathRe  = regexp.MustCompile(`[A-Z]:\\`)
	fsHomeRe     = regexp.MustCompile(`~/`)
	fsGoRe       = regexp.MustCompile(`os\.Open|os\.ReadFile|os\.WriteFile|ioutil\.ReadFile|os\.Create|filepath\.Walk`)
	fsPyRe       = regexp.MustCompile(`open\(|pathlib\.Path\(|shutil\.|os\.path\.`)
	fsJSRe       = regexp.MustCompile(`fs\.readFile|fs\.writeFile|fs\.readFileSync|fs\.writeFileSync|fs\.promises\.`)
	fsShellRe    = regexp.MustCompile(`(^|\||;|&&)\s*(cat|rm|cp|mv|tee|mkdir)\s`)
)

func detectFilesystem(files map[string][]byte) []evidence {
	var out []evidence
	for path, content := range files {
		if shouldSkipFile(path, content) {
			continue
		}
		text := string(content)
		// Quick gate
		if !fsUnixPathRe.MatchString(text) && !fsWinPathRe.MatchString(text) &&
			!fsHomeRe.MatchString(text) && !fsGoRe.MatchString(text) &&
			!fsPyRe.MatchString(text) && !fsJSRe.MatchString(text) &&
			!fsShellRe.MatchString(text) {
			continue
		}
		for i, line := range strings.Split(text, "\n") {
			if fsUnixPathRe.MatchString(line) || fsWinPathRe.MatchString(line) ||
				fsHomeRe.MatchString(line) || fsGoRe.MatchString(line) ||
				fsPyRe.MatchString(line) || fsJSRe.MatchString(line) ||
				fsShellRe.MatchString(line) {
				out = append(out, evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)})
			}
		}
	}
	return out
}
