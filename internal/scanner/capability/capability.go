package capability

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/scanner/meta"
)

// evidence records one line of code that signals a capability is used.
type evidence struct {
	Path    string
	Line    int
	Snippet string
}

// binEvidence carries the extracted executable name alongside the line evidence.
type binEvidence struct {
	evidence
	Bin string
}

// envEvidence carries the extracted env-var name alongside the line evidence.
type envEvidence struct {
	evidence
	Var string
}

// Run detects capability drift between SKILL.md frontmatter and source code.
// Active contradictions (declared:false but used) are SevHigh; silent
// omissions (no declaration but used) are SevMedium. Out-of-scope dimensions
// (declared:true) are skipped. The scanner is gated by paranoia level in the
// engine layer — Run itself does not check Paranoia.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding, errs chan<- scan.RuntimeError) {
	// 0. Capability drift compares a skill's declared requires.* against its
	// own scripts. A compiled application that merely bundles a SKILL.md is
	// not a skill — its source tree is the implementation of a tool — so
	// drift analysis would only produce category-error noise.
	if scan.IsApplicationRepo(repo.Files) {
		out <- scan.Finding{
			Type:     "finding",
			Check:    "capability",
			Severity: scan.SevInfo,
			RuleID:   "cap-app-repo",
			Message:  "repository is a compiled application bundling a skill manifest; capability-drift analysis applies to skills and was skipped",
		}
		return
	}

	// 1. Locate SKILL.md (case-insensitive)
	var skillContent []byte
	for path, content := range repo.Files {
		if strings.EqualFold(path, "SKILL.md") {
			skillContent = content
			break
		}
	}
	if skillContent == nil {
		out <- scan.Finding{
			Type:     "finding",
			Check:    "capability",
			Severity: scan.SevInfo,
			RuleID:   "cap-no-skill-md",
			Message:  "no SKILL.md, capability drift not analyzable",
		}
		return
	}

	// 2. Parse frontmatter
	m, err := meta.ParseFrontmatter(skillContent)
	if err != nil {
		errs <- scan.NewRuntimeError("capability", fmt.Sprintf("parse SKILL.md frontmatter: %v", err))
		return
	}

	// 3. ctx check
	select {
	case <-ctx.Done():
		return
	default:
	}

	// 4. Evidence pass per dimension (each detector applies binary/fixture skip internally)
	netEv := detectNetwork(repo.Files)
	fsEv := detectFilesystem(repo.Files)
	binEv := detectBins(repo.Files)
	envEv := detectEnv(repo.Files)

	// 5. Compare declared vs evidence per dimension, emit at most one finding each.
	emitBoolDrift(out, "network", "cap-net-drift", m.Requires.Network, netEv, m)
	emitBoolDrift(out, "filesystem", "cap-fs-drift", m.Requires.Filesystem, fsEv, m)
	emitBinDrift(out, m, binEv)
	emitEnvDrift(out, m.EnvAllowlist, envEv)
	emitMissingBins(out, m, repo)
}

func emitBoolDrift(out chan<- scan.Finding, dim, ruleID string, declared *bool, ev []evidence, m *meta.SkillMeta) {
	if len(ev) == 0 {
		return
	}
	// For FamClaw skills, skip network/filesystem drift checks as they don't use these fields
	if isFamClawSkill(m) && (dim == "network" || dim == "filesystem") {
		return
	}
	if declared != nil && *declared {
		return // declared true, no drift
	}
	sev := scan.SevMedium
	state := "silent"
	if declared != nil && !*declared {
		sev = scan.SevHigh
		state = "declared false"
	}
	out <- scan.Finding{
		Type:     "finding",
		Check:    "capability",
		Severity: sev,
		RuleID:   ruleID,
		File:     ev[0].Path,
		Line:     ev[0].Line,
		Snippet:  scan.Redact(ev[0].Snippet, 120),
		Message:  fmt.Sprintf("%s %s; %d evidence lines (first shown)", dim, state, len(ev)),
	}
}

func emitBinDrift(out chan<- scan.Finding, m *meta.SkillMeta, ev []binEvidence) {
	if len(ev) == 0 {
		return
	}
	declared := map[string]struct{}{}
	for _, b := range m.Requires.Bins {
		declared[b] = struct{}{}
	}
	for k := range m.Requires.BinsOptional {
		declared[k] = struct{}{}
	}
	undeclared := map[string]binEvidence{}
	for _, e := range ev {
		if _, ok := declared[e.Bin]; ok {
			continue
		}
		if _, seen := undeclared[e.Bin]; !seen {
			undeclared[e.Bin] = e
		}
	}
	if len(undeclared) == 0 {
		return
	}
	names := make([]string, 0, len(undeclared))
	for k := range undeclared {
		names = append(names, k)
	}
	sort.Strings(names)
	first := undeclared[names[0]]
	out <- scan.Finding{
		Type:     "finding",
		Check:    "capability",
		Severity: scan.SevMedium,
		RuleID:   "cap-bin-drift",
		File:     first.Path,
		Line:     first.Line,
		Snippet:  scan.Redact(first.Snippet, 120),
		Message:  fmt.Sprintf("undeclared bins: %s (%d total evidence lines)", strings.Join(names, ", "), len(ev)),
	}
}

var envWhitelist = map[string]struct{}{
	"PATH": {}, "HOME": {}, "USER": {}, "SHELL": {}, "TERM": {},
	"LANG": {}, "PWD": {}, "TMPDIR": {}, "LOGNAME": {},
}

func emitEnvDrift(out chan<- scan.Finding, declaredEnv []string, ev []envEvidence) {
	if len(ev) == 0 {
		return
	}
	declared := map[string]struct{}{}
	for _, v := range declaredEnv {
		declared[v] = struct{}{}
	}
	undeclared := map[string]envEvidence{}
	total := 0
	for _, e := range ev {
		if _, w := envWhitelist[e.Var]; w {
			continue
		}
		if strings.HasPrefix(e.Var, "LC_") {
			continue
		}
		total++
		if _, ok := declared[e.Var]; ok {
			continue
		}
		if _, seen := undeclared[e.Var]; !seen {
			undeclared[e.Var] = e
		}
	}
	if len(undeclared) == 0 {
		return
	}
	names := make([]string, 0, len(undeclared))
	for k := range undeclared {
		names = append(names, k)
	}
	sort.Strings(names)
	first := undeclared[names[0]]
	out <- scan.Finding{
		Type:     "finding",
		Check:    "capability",
		Severity: scan.SevMedium,
		RuleID:   "cap-env-drift",
		File:     first.Path,
		Line:     first.Line,
		Snippet:  scan.Redact(first.Snippet, 120),
		Message:  fmt.Sprintf("undeclared env vars: %s (%d total evidence lines)", strings.Join(names, ", "), total),
	}
}

// isBinary returns true if the first 512 bytes contain a null byte.
func isBinary(data []byte) bool {
	n := 512
	if len(data) < n {
		n = len(data)
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// isFamClawSkill returns true if the skill appears to be a FamClaw skill
// based on the presence of FamClaw-specific fields.
func isFamClawSkill(m *meta.SkillMeta) bool {
	// FamClaw skills typically have env_allowlist or trigger defined
	return len(m.EnvAllowlist) > 0 || m.Trigger.Mode != "" || len(m.Trigger.Keywords) > 0
}

// emitMissingBins checks that all declared bins actually exist in the bin/ directory
func emitMissingBins(out chan<- scan.Finding, m *meta.SkillMeta, repo *fetch.Repo) {
	for _, bin := range m.Requires.Bins {
		found := false
		for path := range repo.Files {
			if strings.HasPrefix(path, "bin/") && filepath.Base(path) == bin {
				found = true
				break
			}
		}
		if !found {
			out <- scan.Finding{
				Type:     "finding",
				Check:    "capability",
				Severity: scan.SevMedium,
				RuleID:   "cap-bin-missing",
				File:     "SKILL.md",
				Message:  fmt.Sprintf("declared bin %q not found in bin/", bin),
			}
		}
	}
}

// shouldSkipFile returns true for binary blobs, the SKILL.md, and test fixtures.
func shouldSkipFile(path string, content []byte) bool {
	if strings.EqualFold(path, "SKILL.md") {
		return true
	}
	if strings.HasSuffix(path, "_test.go") {
		return true
	}
	if strings.Contains(path, "testdata/") || strings.Contains(path, "testfixture/") {
		return true
	}
	if isBinary(content) {
		return true
	}
	return false
}
