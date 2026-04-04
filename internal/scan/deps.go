package scan

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// Dependency represents a single parsed dependency.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string // "Go", "npm", "PyPI", "crates.io", "RubyGems", "Maven"
}

// ParseDeps extracts dependencies from all recognized lockfiles in the repo.
func ParseDeps(repo *fetch.Repo) []Dependency {
	var deps []Dependency

	for path, content := range repo.Files {
		var parsed []Dependency
		base := baseName(path)

		switch {
		case base == "go.mod":
			parsed = parseGoMod(string(content))
		case base == "package-lock.json":
			parsed = parsePackageLockJSON(content)
		case base == "yarn.lock":
			parsed = parseYarnLock(string(content))
		case base == "requirements.txt":
			parsed = parseRequirementsTxt(string(content))
		case base == "Pipfile.lock":
			parsed = parsePipfileLock(content)
		case base == "Cargo.lock":
			parsed = parseCargoLock(string(content))
		case base == "Gemfile.lock":
			parsed = parseGemfileLock(string(content))
		case base == "pom.xml":
			parsed = parsePomXML(string(content))
		}

		deps = append(deps, parsed...)
	}

	return deps
}

// baseName returns the last path component.
func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

// parseGoMod parses go.mod require directives.
func parseGoMod(content string) []Dependency {
	var deps []Dependency
	inRequire := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require(") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 && !strings.HasPrefix(parts[0], "//") {
				deps = append(deps, Dependency{
					Name:      parts[0],
					Version:   parts[1],
					Ecosystem: "Go",
				})
			}
		} else if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, Dependency{
					Name:      parts[1],
					Version:   parts[2],
					Ecosystem: "Go",
				})
			}
		}
	}

	return deps
}

// parsePackageLockJSON parses package-lock.json.
func parsePackageLockJSON(content []byte) []Dependency {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil
	}

	var deps []Dependency

	// Try v2/v3 "packages" field first
	if pkgsRaw, ok := raw["packages"]; ok {
		var packages map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(pkgsRaw, &packages); err == nil {
			for path, pkg := range packages {
				if path == "" || pkg.Version == "" {
					continue
				}
				// path is like "node_modules/lodash"
				name := path
				if idx := strings.LastIndex(path, "node_modules/"); idx >= 0 {
					name = path[idx+len("node_modules/"):]
				}
				deps = append(deps, Dependency{
					Name:      name,
					Version:   pkg.Version,
					Ecosystem: "npm",
				})
			}
			return deps
		}
	}

	// Fall back to v1 "dependencies" field
	if depsRaw, ok := raw["dependencies"]; ok {
		var dependencies map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(depsRaw, &dependencies); err == nil {
			for name, dep := range dependencies {
				if dep.Version == "" {
					continue
				}
				deps = append(deps, Dependency{
					Name:      name,
					Version:   dep.Version,
					Ecosystem: "npm",
				})
			}
		}
	}

	return deps
}

// parseYarnLock parses yarn.lock files.
func parseYarnLock(content string) []Dependency {
	var deps []Dependency

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Lines like: "lodash@^4.17.21":
		// or: lodash@^4.17.21:
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, " ") {
			line = strings.TrimSuffix(line, ":")
			line = strings.Trim(line, "\"")
			// Split on @ to get name and version constraint
			if atIdx := strings.LastIndex(line, "@"); atIdx > 0 {
				name := line[:atIdx]
				deps = append(deps, Dependency{
					Name:      name,
					Version:   line[atIdx+1:],
					Ecosystem: "npm",
				})
			}
		}

		// Pick up resolved version if present
		if strings.HasPrefix(line, "version ") {
			// Update last dep's version to the resolved one
			ver := strings.TrimPrefix(line, "version ")
			ver = strings.Trim(ver, "\"")
			if len(deps) > 0 && ver != "" {
				deps[len(deps)-1].Version = ver
			}
		}
	}

	return deps
}

// parseRequirementsTxt parses Python requirements.txt.
func parseRequirementsTxt(content string) []Dependency {
	var deps []Dependency

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		if parts := strings.SplitN(line, "==", 2); len(parts) == 2 {
			deps = append(deps, Dependency{
				Name:      strings.TrimSpace(parts[0]),
				Version:   strings.TrimSpace(parts[1]),
				Ecosystem: "PyPI",
			})
		}
	}

	return deps
}

// parsePipfileLock parses Pipfile.lock JSON.
func parsePipfileLock(content []byte) []Dependency {
	var raw map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil
	}

	var deps []Dependency
	if defaults, ok := raw["default"]; ok {
		for name, pkg := range defaults {
			ver := pkg.Version
			ver = strings.TrimPrefix(ver, "==")
			if ver == "" {
				continue
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   ver,
				Ecosystem: "PyPI",
			})
		}
	}

	return deps
}

// parseCargoLock parses Cargo.lock [[package]] blocks.
func parseCargoLock(content string) []Dependency {
	var deps []Dependency
	var name, version string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		if line == "[[package]]" {
			if name != "" && version != "" {
				deps = append(deps, Dependency{
					Name:      name,
					Version:   version,
					Ecosystem: "crates.io",
				})
			}
			name = ""
			version = ""
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		} else if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
	}

	// Don't forget last block
	if name != "" && version != "" {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "crates.io",
		})
	}

	return deps
}

// parseGemfileLock parses Gemfile.lock GEM/specs section.
func parseGemfileLock(content string) []Dependency {
	var deps []Dependency
	inSpecs := false

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		if trimmed == "specs:" {
			inSpecs = true
			continue
		}

		// Sections end when we hit a non-indented line (not starting with space)
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
			continue
		}

		if inSpecs {
			// Gem lines look like: "    rails (7.0.4)" (4-space indent for top-level gems)
			// Sub-dependencies have 6+ spaces; we capture all
			if paren := strings.Index(trimmed, " ("); paren > 0 {
				name := trimmed[:paren]
				ver := strings.Trim(trimmed[paren+2:], ")")
				if !strings.ContainsAny(ver, "<>~!=") {
					deps = append(deps, Dependency{
						Name:      name,
						Version:   ver,
						Ecosystem: "RubyGems",
					})
				}
			}
		}
	}

	return deps
}

// parsePomXML parses Maven pom.xml for <dependency> blocks.
var pomDepRegex = regexp.MustCompile(`(?s)<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?`)

func parsePomXML(content string) []Dependency {
	var deps []Dependency

	matches := pomDepRegex.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		groupID := m[1]
		artifactID := m[2]
		version := ""
		if len(m) > 3 {
			version = m[3]
		}
		if version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      groupID + ":" + artifactID,
			Version:   version,
			Ecosystem: "Maven",
		})
	}

	return deps
}
