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
	var removed []string
	for name := range prevParams {
		if _, ok := curParams[name]; !ok {
			removed = append(removed, name)
		}
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		parts = append(parts, "removed parameters: "+strings.Join(removed, ", "))
	}
	for name, curDesc := range curParams {
		if prevDesc, ok := prevParams[name]; ok && prevDesc != curDesc {
			parts = append(parts, fmt.Sprintf("parameter %q description changed", name))
		}
	}
	if annotationsDiffer(prev.Annotations, cur.Annotations) {
		parts = append(parts, "annotations changed")
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// annotationsDiffer reports whether two Annotations differ, including nil-vs-set.
func annotationsDiffer(a, b *Annotations) bool {
	if (a == nil) != (b == nil) {
		return true
	}
	if a == nil {
		return false
	}
	return ptrBoolDiffers(a.ReadOnlyHint, b.ReadOnlyHint) ||
		ptrBoolDiffers(a.DestructiveHint, b.DestructiveHint) ||
		ptrBoolDiffers(a.IdempotentHint, b.IdempotentHint) ||
		ptrBoolDiffers(a.OpenWorldHint, b.OpenWorldHint)
}

// ptrBoolDiffers reports whether two *bool values differ, treating nil as absent.
func ptrBoolDiffers(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return true
	}
	if a == nil {
		return false
	}
	return *a != *b
}

// paramSet maps param name -> description for diffing.
func paramSet(td ToolDef) map[string]string {
	m := map[string]string{}
	for _, p := range td.Params {
		m[p.Name] = p.Description
	}
	return m
}
