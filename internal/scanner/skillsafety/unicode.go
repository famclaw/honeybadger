package skillsafety

import "regexp"

// suspiciousCodepoints maps zero-width and invisible Unicode characters
// to descriptive names for reporting.
var suspiciousCodepoints = map[rune]string{
	'\u200B': "zero_width_space",
	'\u200C': "zero_width_non_joiner",
	'\u200D': "zero_width_joiner",
	'\uFEFF': "byte_order_mark_in_body",
	'\u00AD': "soft_hyphen",
}

// rtlCodepoints maps directional override and isolate characters
// to descriptive names for reporting.
var rtlCodepoints = map[rune]string{
	'\u200E': "left_to_right_mark",
	'\u200F': "right_to_left_mark",
	'\u202A': "left_to_right_embedding",
	'\u202B': "right_to_left_embedding",
	'\u202C': "pop_directional_formatting",
	'\u202D': "left_to_right_override",
	'\u202E': "right_to_left_override",
	'\u2066': "left_to_right_isolate",
	'\u2067': "right_to_left_isolate",
	'\u2068': "first_strong_isolate",
	'\u2069': "pop_directional_isolate",
}

var htmlCommentRe = regexp.MustCompile(`<!--[\s\S]*?-->`)

// CountZeroWidth counts zero-width and invisible Unicode characters.
func CountZeroWidth(s string) int {
	n := 0
	for _, r := range s {
		if _, ok := suspiciousCodepoints[r]; ok {
			n++
		}
	}
	return n
}

// CountRTLOverrides counts right-to-left override characters.
func CountRTLOverrides(s string) int {
	n := 0
	for _, r := range s {
		if _, ok := rtlCodepoints[r]; ok {
			n++
		}
	}
	return n
}

// ExtractHTMLComments returns all HTML comment blocks found in the text.
func ExtractHTMLComments(s string) []string {
	matches := htmlCommentRe.FindAllString(s, -1)
	if matches == nil {
		return nil
	}
	return matches
}
