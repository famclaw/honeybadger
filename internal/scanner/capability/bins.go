package capability

import (
	"regexp"
	"strings"
)

var (
	binsPyRe       = regexp.MustCompile(`subprocess\.(?:run|Popen)\(\["([a-zA-Z0-9_.-]+)"`)
	binsGoRe       = regexp.MustCompile(`exec\.(?:Command|CommandContext)\(\s*(?:ctx,\s*)?"([a-zA-Z0-9_.-]+)"`)
	binsJSRe       = regexp.MustCompile(`(?:child_process\.(?:spawn|exec)|execSync)\("([a-zA-Z0-9_.-]+)"`)
	binsBacktickRe = regexp.MustCompile("`([a-zA-Z0-9_.-]+)(?:\\s|`)")
	binsTokRe      = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
)

var shellBuiltins = map[string]struct{}{
	"if": {}, "for": {}, "while": {}, "function": {}, "case": {},
	"[": {}, "[[": {}, "echo": {}, "cd": {}, "export": {},
	"local": {}, "return": {}, "exit": {}, "set": {}, "do": {},
	"done": {}, "then": {}, "fi": {}, "else": {}, "elif": {}, "esac": {},
}

func detectBins(files map[string][]byte) []binEvidence {
	var out []binEvidence
	for path, content := range files {
		if shouldSkipFile(path, content) {
			continue
		}
		text := string(content)
		for i, line := range strings.Split(text, "\n") {
			for _, m := range binsPyRe.FindAllStringSubmatch(line, -1) {
				out = append(out, binEvidence{evidence: evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)}, Bin: m[1]})
			}
			for _, m := range binsGoRe.FindAllStringSubmatch(line, -1) {
				out = append(out, binEvidence{evidence: evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)}, Bin: m[1]})
			}
			for _, m := range binsJSRe.FindAllStringSubmatch(line, -1) {
				out = append(out, binEvidence{evidence: evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)}, Bin: m[1]})
			}
			for _, m := range binsBacktickRe.FindAllStringSubmatch(line, -1) {
				if _, builtin := shellBuiltins[m[1]]; !builtin {
					out = append(out, binEvidence{evidence: evidence{Path: path, Line: i + 1, Snippet: strings.TrimSpace(line)}, Bin: m[1]})
				}
			}
		}

		// Shell script detection: file ends in .sh OR first line has #! with bash/sh
		isShell := strings.HasSuffix(path, ".sh")
		if !isShell {
			firstLine := text
			if nl := strings.IndexByte(firstLine, '\n'); nl >= 0 {
				firstLine = firstLine[:nl]
			}
			if strings.HasPrefix(firstLine, "#!") && (strings.Contains(firstLine, "bash") || strings.Contains(firstLine, "sh")) {
				isShell = true
			}
		}
		if !isShell {
			continue
		}
		for i, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			fields := strings.Fields(trimmed)
			if len(fields) == 0 {
				continue
			}
			tok := fields[0]
			if _, builtin := shellBuiltins[tok]; builtin {
				continue
			}
			// Only count tokens that look like bin names
			if !binsTokRe.MatchString(tok) {
				continue
			}
			out = append(out, binEvidence{evidence: evidence{Path: path, Line: i + 1, Snippet: trimmed}, Bin: tok})
		}
	}
	return out
}
