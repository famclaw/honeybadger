package skillsafety

import (
	"sort"
	"unicode"
)

// scriptEntry maps a Unicode script table to its display name.
type scriptEntry struct {
	table *unicode.RangeTable
	name  string
}

var knownScripts = []scriptEntry{
	{unicode.Latin, "Latin"},
	{unicode.Han, "Han"},
	{unicode.Cyrillic, "Cyrillic"},
	{unicode.Arabic, "Arabic"},
	{unicode.Hangul, "Hangul"},
	{unicode.Hiragana, "Hiragana"},
	{unicode.Katakana, "Katakana"},
}

// DetectLanguages analyzes text by Unicode script block and returns the
// primary language, all detected languages, and any unexpected scripts.
// A script is "unexpected" if the text is >80% one script but contains
// >20 characters of another script.
func DetectLanguages(text string) (primary string, all []string, unexpected []string) {
	counts := make(map[string]int)
	total := 0

	for _, r := range text {
		if unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsDigit(r) || unicode.IsSymbol(r) {
			continue
		}
		for _, se := range knownScripts {
			if unicode.Is(se.table, r) {
				counts[se.name]++
				total++
				break
			}
		}
	}

	if total == 0 {
		return "", nil, nil
	}

	// Determine primary as the script with the highest count.
	maxCount := 0
	for name, c := range counts {
		if c > maxCount {
			maxCount = c
			primary = name
		}
	}

	// Collect all detected scripts sorted alphabetically for determinism.
	for name := range counts {
		all = append(all, name)
	}
	sort.Strings(all)

	// A script is "unexpected" if:
	//   - the primary script covers >80% of classified characters
	//   - the non-primary script has >20 characters
	primaryRatio := float64(maxCount) / float64(total)
	if primaryRatio > 0.80 {
		for name, c := range counts {
			if name != primary && c > 20 {
				unexpected = append(unexpected, name)
			}
		}
		sort.Strings(unexpected)
	}

	return primary, all, unexpected
}
