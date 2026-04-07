package rules

// MatchLine tests all compiled patterns against a single line of text.
// Returns descriptions of matched patterns.
func (r *Rule) MatchLine(line string) []string {
	if r.Kind != "pattern" {
		return nil
	}
	var matches []string
	for _, cp := range r.compiled {
		if cp.Re.FindString(line) != "" {
			matches = append(matches, cp.Description)
		}
	}
	return matches
}

// HasPackage checks if a dictionary rule contains the given package name.
func (r *Rule) HasPackage(pkg string) bool {
	if r.Kind != "dictionary" {
		return false
	}
	for _, p := range r.Packages {
		if p == pkg {
			return true
		}
	}
	return false
}
