package mcptool

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/scan"
)

// writeVerbRe matches write/network/exec verbs in a tool name or description.
var writeVerbRe = regexp.MustCompile(`(?i)\b(write|create|insert|update|patch|put|set|send|post|upload|save|append|modify|edit|push|delete|remove|drop|truncate|exec|execute|spawn|deploy|publish|fetch|download)\b`)

// suspectParamNames are parameter names implying a write payload or network target.
var suspectParamNames = map[string]struct{}{
	"content": {}, "body": {}, "data": {}, "payload": {}, "message": {},
	"url": {}, "endpoint": {}, "host": {}, "uri": {},
}

// detectCapability runs detection 4 layers 1-3 (manifest-only). Layer 4
// (source evidence) is added in Task 12 via escalateIfSourceConfirms.
//
// repoFiles may be nil; it is unused at layers 1-3 and accepted so the
// signature is stable for Task 12.
func detectCapability(tools []ToolDef, repoFiles map[string][]byte) []scan.Finding {
	var out []scan.Finding
	for _, td := range tools {
		// Layer 1: no annotations at all.
		if td.Annotations == nil {
			out = append(out, scan.Finding{
				Type:     "finding",
				Check:    "mcptool",
				Severity: scan.SevLow,
				RuleID:   "mcp-tool-unannotated",
				File:     td.SourceFile,
				Message:  fmt.Sprintf("Tool %q declares no annotations; capability cannot be verified", td.Name),
			})
			continue
		}
		ro := td.Annotations.ReadOnlyHint
		if ro == nil || !*ro {
			continue // not declared read-only — nothing to contradict
		}

		// Layer 2: write/network verb in name or description.
		if writeVerbRe.MatchString(td.Name) || writeVerbRe.MatchString(td.Description) {
			out = append(out, mismatchFinding(td,
				"declared readOnlyHint:true but name/description implies write or network access"))
			continue
		}
		// Layer 3: suspect parameter names.
		var bad []string
		for _, p := range td.Params {
			if _, ok := suspectParamNames[strings.ToLower(p.Name)]; ok {
				bad = append(bad, p.Name)
			}
		}
		if len(bad) > 0 {
			out = append(out, mismatchFinding(td,
				fmt.Sprintf("declared readOnlyHint:true but has write/network parameters: %s", strings.Join(bad, ", "))))
		}
	}
	return out
}

func mismatchFinding(td ToolDef, detail string) scan.Finding {
	return scan.Finding{
		Type:     "finding",
		Check:    "mcptool",
		Severity: scan.SevMedium,
		RuleID:   "mcp-capability-mismatch",
		File:     td.SourceFile,
		Message:  fmt.Sprintf("Tool %q capability mismatch: %s", td.Name, detail),
	}
}
