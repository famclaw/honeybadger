package mcptool

import (
	"fmt"
	"sort"
	"strings"

	"github.com/famclaw/honeybadger/internal/scan"
)

// detectRugPull runs detection 5: field-level diff of the current tools
// against an approved baseline. Changes to an already-approved tool are HIGH;
// brand-new tools are MEDIUM; removed tools yield no finding.
func detectRugPull(current, baseline []ToolDef) []scan.Finding {
	base := map[string]ToolDef{}
	for _, t := range baseline {
		base[t.Name] = t
	}
	var out []scan.Finding
	for _, cur := range current {
		prev, known := base[cur.Name]
		if !known {
			out = append(out, scan.Finding{
				Type:     "finding",
				Check:    "mcptool",
				Severity: scan.SevMedium,
				RuleID:   "mcp-rug-pull",
				Message:  fmt.Sprintf("Tool %q is new since the approved baseline", cur.Name),
			})
			continue
		}
		if diff := toolDiff(prev, cur); diff != "" {
			out = append(out, scan.Finding{
				Type:     "finding",
				Check:    "mcptool",
				Severity: scan.SevHigh,
				RuleID:   "mcp-rug-pull",
				Message:  fmt.Sprintf("Approved tool %q changed since baseline: %s", cur.Name, diff),
			})
		}
	}
	return out
}

// toolDiff returns a human-readable summary of what changed between an approved
// tool and its current definition, or "" if nothing changed.
func toolDiff(prev, cur ToolDef) string {
	var parts []string
	if prev.Description != cur.Description {
		parts = append(parts, "description changed")
	}
	prevParams := paramSet(prev)
	curParams := paramSet(cur)
	var added []string
	for name := range curParams {
		if _, ok := prevParams[name]; !ok {
			added = append(added, name)
		}
	}
	if len(added) > 0 {
		sort.Strings(added)
		parts = append(parts, "new parameters: "+strings.Join(added, ", "))
	}
	for name, curDesc := range curParams {
		if prevDesc, ok := prevParams[name]; ok && prevDesc != curDesc {
			parts = append(parts, fmt.Sprintf("parameter %q description changed", name))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// paramSet maps param name -> description for diffing.
func paramSet(td ToolDef) map[string]string {
	m := map[string]string{}
	for _, p := range td.Params {
		m[p.Name] = p.Description
	}
	return m
}
