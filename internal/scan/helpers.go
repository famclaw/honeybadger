package scan

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]bool{
	".git":        true,
	"node_modules": true,
	"vendor":      true,
	"__pycache__": true,
	".venv":       true,
	"dist":        true,
	"build":       true,
}

var binaryExts = map[string]bool{
	".png":  true,
	".jpg":  true,
	".gif":  true,
	".pdf":  true,
	".zip":  true,
	".tar":  true,
	".gz":   true,
	".wasm": true,
	".bin":  true,
	".exe":  true,
}

// WalkCode walks a directory tree, skipping common non-source directories and
// binary files. It calls fn with the absolute path and the path relative to dir.
func WalkCode(dir string, fn func(path, rel string)) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if binaryExts[ext] {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		fn(path, rel)
		return nil
	})
}

// IsPlaceholder checks if a line contains placeholder indicators.
func IsPlaceholder(line string) bool {
	lower := strings.ToLower(line)
	for _, p := range []string{
		"your_key", "your-key", "example", "placeholder",
		"xxxx", "changeme", "todo", "${",
		"process.env", "os.getenv", "os.environ", "config.", "***",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// Redact truncates a string to maxLen and replaces long alphanumeric runs
// with partial redaction.
func Redact(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	result := []byte(s)
	i := 0
	for i < len(result) {
		// Find start of alphanumeric run
		start := i
		for i < len(result) && isAlphaNumOrPlus(result[i]) {
			i++
		}
		runLen := i - start
		if runLen >= 30 {
			// Replace middle with asterisks, keep first 4 and last 4
			keep := 4
			replaced := make([]byte, 0, len(result))
			replaced = append(replaced, result[:start+keep]...)
			for j := 0; j < runLen-2*keep; j++ {
				replaced = append(replaced, '*')
			}
			replaced = append(replaced, result[i-keep:]...)
			result = replaced
			i = start + runLen // maintain position
		}
		if i < len(result) {
			i++
		}
	}
	return string(result)
}

func isAlphaNumOrPlus(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '+' || b == '/'
}

// EditDistance computes the Levenshtein distance between two strings.
func EditDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	m, n := len(ra), len(rb)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
		dp[i][0] = i
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if ra[i-1] == rb[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				del := dp[i-1][j]
				ins := dp[i][j-1]
				sub := dp[i-1][j-1]
				mn := del
				if ins < mn {
					mn = ins
				}
				if sub < mn {
					mn = sub
				}
				dp[i][j] = 1 + mn
			}
		}
	}
	return dp[m][n]
}

// IsBinaryFile reads the first 512 bytes of a file and returns true if
// null bytes are found.
func IsBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}
	return false
}
