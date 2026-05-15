package mcptool

import (
	"fmt"

	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/scanner/skillsafety"
)

// countTagChars counts Unicode Tags-block runes (U+E0000..U+E007F), the
// ASCII-smuggling vector not covered by skillsafety's zero-width set.
func countTagChars(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0xE0000 && r <= 0xE007F {
			n++
		}
	}
	return n
}

// detectUnicode runs detection 2: obfuscation characters in tool text fields.
func detectUnicode(tools []ToolDef) []scan.Finding {
	var out []scan.Finding
	for _, td := range tools {
		for _, tf := range textFields(td) {
			zw := skillsafety.CountZeroWidth(tf.Text)
			rtl := skillsafety.CountRTLOverrides(tf.Text)
			tags := countTagChars(tf.Text)
			homo := skillsafety.DetectHomoglyphs(tf.Text)

			if zw+rtl+tags > 0 {
				out = append(out, scan.Finding{
					Type:     "finding",
					Check:    "mcptool",
					Severity: scan.SevHigh,
					RuleID:   "mcp-unicode-obfuscation",
					File:     td.SourceFile,
					Message: fmt.Sprintf("Hidden Unicode in tool %q field %s: %d zero-width, %d RTL, %d tag-block",
						td.Name, tf.Label, zw, rtl, tags),
				})
			}
			if len(homo) > 0 {
				out = append(out, scan.Finding{
					Type:     "finding",
					Check:    "mcptool",
					Severity: scan.SevMedium,
					RuleID:   "mcp-unicode-homoglyph",
					File:     td.SourceFile,
					Message: fmt.Sprintf("Homoglyph words in tool %q field %s: %v",
						td.Name, tf.Label, homo),
				})
			}
		}
	}
	return out
}
