package scan

import "strings"

// IsMarkdown reports whether a path is a Markdown document.
func IsMarkdown(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".markdown")
}

// CodeBlockLines parses Markdown content and returns a set of 1-indexed line
// numbers that fall inside a code block — either fenced (``` or ~~~) or
// indented (four spaces / a tab). Lines absent from the set are prose:
// paragraphs, headings, list items, and table cells.
//
// A detector match in prose merely *describes* a pattern; a match inside a
// code block is an example snippet. Neither is the executable artifact, but
// the distinction lets the caller drop prose noise while still surfacing
// snippets informationally.
func CodeBlockLines(content []byte) map[int]bool {
	lines := strings.Split(string(content), "\n")
	inCode := make(map[int]bool, len(lines))

	inFence := false
	fenceMarker := ""
	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if inFence {
			inCode[lineNum] = true
			if strings.HasPrefix(trimmed, fenceMarker) {
				inFence = false
			}
			continue
		}

		if strings.HasPrefix(trimmed, "```") {
			inFence, fenceMarker = true, "```"
			inCode[lineNum] = true
			continue
		}
		if strings.HasPrefix(trimmed, "~~~") {
			inFence, fenceMarker = true, "~~~"
			inCode[lineNum] = true
			continue
		}

		// Indented code block: >=4 leading spaces or a leading tab, non-blank.
		if trimmed != "" && (strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t")) {
			inCode[lineNum] = true
		}
	}
	return inCode
}

// CodeBlockOnly returns content with every prose line blanked, preserving
// line numbering and code-block content. Use it to feed a content-level
// detector that should ignore Markdown prose.
func CodeBlockOnly(content []byte) []byte {
	inCode := CodeBlockLines(content)
	lines := strings.Split(string(content), "\n")
	for i := range lines {
		if !inCode[i+1] {
			lines[i] = ""
		}
	}
	return []byte(strings.Join(lines, "\n"))
}
