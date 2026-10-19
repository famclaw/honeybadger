package docs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoPath joins path elements onto the repo root (docs/..).
func repoPath(t *testing.T, elem ...string) string {
	t.Helper()
	return filepath.Join(append([]string{docsDir(t), ".."}, elem...)...)
}

// pathExists reports whether a path exists relative to the repo root.
func pathExists(t *testing.T, elem ...string) bool {
	t.Helper()
	_, err := os.Stat(repoPath(t, elem...))
	return err == nil
}

// funcDefinedIn reports whether "func <name>(" appears anywhere in the given
// source directory (searching every .go file, non-recursively).
func funcDefinedIn(t *testing.T, dir, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(repoPath(t, dir))
	if err != nil {
		return false
	}
	needle := "func " + name + "("
	needleMethod := ") " + name + "(" // method receiver form
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(repoPath(t, dir, e.Name()))
		if err != nil {
			continue
		}
		s := string(b)
		if strings.Contains(s, needle) || strings.Contains(s, needleMethod) {
			return true
		}
	}
	return false
}

// TestAGENTSMD_OrientationSectionExists verifies the Codebase orientation
// section — the whole point of this doc — is present with its subsections.
func TestAGENTSMD_OrientationSectionExists(t *testing.T) {
	doc := readSource(t, "AGENTS.md")
	for _, heading := range []string{
		"## Codebase orientation",
		"### Package map",
		"### Scanners",
		"### Entry points",
		`"Where does X live?"`,
		"### Notable sharp edges",
	} {
		if !strings.Contains(doc, heading) {
			t.Errorf("AGENTS.md must contain orientation heading %q", heading)
		}
	}
}

// TestAGENTSMD_PackageMapMatchesSource verifies every internal/ package named
// in the orientation package map actually exists as a directory.
func TestAGENTSMD_PackageMapMatchesSource(t *testing.T) {
	_ = readSource(t, "AGENTS.md") // ensure doc is present
	packages := []string{
		"engine", "fetch", "ignore", "report",
		"rules", "scan", "scanner", "store", "testfixture",
	}
	for _, p := range packages {
		if !pathExists(t, "internal", p) {
			t.Errorf("AGENTS.md package map lists internal/%s but the directory does not exist", p)
		}
	}
}

// TestAGENTSMD_ScannersMatchSource verifies the doc's "8 total" scanner claim
// and that every named scanner has a package directory.
func TestAGENTSMD_ScannersMatchSource(t *testing.T) {
	doc := readSource(t, "AGENTS.md")
	if !strings.Contains(doc, "Individual scanners (8 total)") {
		t.Error("AGENTS.md must state the scanner count as '8 total'")
	}
	scanners := []string{
		"secrets", "cve", "supplychain", "meta",
		"capability", "skillsafety", "mcptool", "attestation",
	}
	entries, err := os.ReadDir(repoPath(t, "internal", "scanner"))
	if err != nil {
		t.Fatalf("reading internal/scanner: %v", err)
	}
	got := 0
	for _, e := range entries {
		if e.IsDir() {
			got++
		}
	}
	if got != len(scanners) {
		t.Errorf("AGENTS.md claims 8 scanners; internal/scanner has %d subdirectories", got)
	}
	for _, s := range scanners {
		if !pathExists(t, "internal", "scanner", s) {
			t.Errorf("AGENTS.md lists scanner %q but internal/scanner/%s does not exist", s, s)
		}
	}
}

// TestAGENTSMD_QuickIndexPathsExist verifies every "Where does X live?"
// pointer resolves to a real file or directory on disk.
func TestAGENTSMD_QuickIndexPathsExist(t *testing.T) {
	_ = readSource(t, "AGENTS.md")
	paths := []string{
		"internal/scan",
		"cmd/honeybadger/main.go",
		"internal/scanner/cve",
		"internal/report/llm.go",
		"rules",
		"internal/scan/fileclass.go",
		"cmd/honeybadger/mcp.go",
		"internal/rules",
		"internal/testfixture",
		"internal/report",
		"internal/ignore",
		"internal/scanner/attestation",
		"internal/scanner/capability",
		"internal/scanner/supplychain",
		"internal/scan/scan.go",
	}
	for _, p := range paths {
		if !pathExists(t, filepath.FromSlash(p)) {
			t.Errorf("AGENTS.md quick index points to %q but it does not exist", p)
		}
	}
}

// TestAGENTSMD_NamedFunctionsExist verifies functions/types called out in the
// orientation section (package map + sharp edges) are actually defined where
// the doc says they are.
func TestAGENTSMD_NamedFunctionsExist(t *testing.T) {
	_ = readSource(t, "AGENTS.md")
	cases := []struct {
		dir  string
		name string
	}{
		{"internal/engine", "BuildScannerList"},
		{"internal/engine", "ComputeVerdict"},
		{"internal/engine", "CheckToolHash"},
		{"internal/fetch", "Route"},
		{"internal/fetch", "parseGitHubURL"},
		{"internal/ignore", "Parse"},
		{"internal/report", "NewNDJSONEmitter"},
		{"internal/report", "NewTextEmitter"},
		{"internal/report", "CallLLM"},
		{"internal/report", "AssembleLLMPrompt"},
		{"internal/report", "buildSourceBlock"},
		{"internal/rules", "Load"},
		{"internal/scan", "RunAll"},
		{"internal/scanner/supplychain", "isBinaryContent"},
		{"internal/scanner/supplychain", "extractDependencyNames"},
		{"internal/scanner/mcptool", "detectShadowing"},
		{"internal/scanner/mcptool", "detectInjectionWithHits"},
	}
	for _, c := range cases {
		if !funcDefinedIn(t, c.dir, c.name) {
			t.Errorf("AGENTS.md references %s but it is not defined in %s", c.name, c.dir)
		}
	}
}
