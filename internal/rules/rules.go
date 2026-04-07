package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	rulesdata "github.com/famclaw/honeybadger/rules"
	"gopkg.in/yaml.v3"
)

// Load reads rules from the embedded FS, then merges user-provided rules
// from userDir (or $HONEYBADGER_RULES_DIR or ~/.honeybadger/rules/).
// User rules with the same ID replace embedded ones.
func Load(userDir string) (*RuleSet, error) {
	byID := make(map[string]*Rule)

	// 1. Load embedded rules.
	if err := loadFromFS(rulesdata.FS, byID); err != nil {
		return nil, fmt.Errorf("embedded rules: %w", err)
	}

	// 2. Load user rules (override by ID).
	dir := userDir
	if dir == "" {
		dir = os.Getenv("HONEYBADGER_RULES_DIR")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			candidate := filepath.Join(home, ".honeybadger", "rules")
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				dir = candidate
			}
		}
	}
	if dir != "" {
		if err := loadFromDir(dir, byID); err != nil {
			return nil, fmt.Errorf("user rules %s: %w", dir, err)
		}
	}

	// 3. Build RuleSet.
	rs := &RuleSet{
		byScanner: make(map[string][]*Rule),
	}
	for _, r := range byID {
		rs.all = append(rs.all, r)
		rs.byScanner[r.Scanner] = append(rs.byScanner[r.Scanner], r)
	}
	return rs, nil
}

func loadFromFS(fsys fs.FS, byID map[string]*Rule) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		return parseAndAdd(data, path, byID)
	})
}

func loadFromDir(dir string, byID map[string]*Rule) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		return parseAndAdd(data, path, byID)
	})
}

func parseAndAdd(data []byte, path string, byID map[string]*Rule) error {
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := validateRule(&r); err != nil {
		return fmt.Errorf("validating %s: %w", path, err)
	}
	if err := compileRule(&r); err != nil {
		return fmt.Errorf("compiling %s: %w", path, err)
	}
	byID[r.ID] = &r
	return nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
