package mcptool

import "fmt"

// textField is one analyzable text value of a tool definition.
type textField struct {
	Label string // e.g. "description", "param[path].title"
	Text  string
}

// textFields enumerates every LLM-visible text value of a tool: the tool
// description, and each parameter's description, title, default, and enum
// values. Empty values are skipped.
func textFields(td ToolDef) []textField {
	var out []textField
	add := func(label, text string) {
		if text != "" {
			out = append(out, textField{Label: label, Text: text})
		}
	}
	add("description", td.Description)
	for _, p := range td.Params {
		add(fmt.Sprintf("param[%s].description", p.Name), p.Description)
		add(fmt.Sprintf("param[%s].title", p.Name), p.Title)
		add(fmt.Sprintf("param[%s].default", p.Name), p.Default)
		for i, e := range p.Enum {
			add(fmt.Sprintf("param[%s].enum[%d]", p.Name, i), e)
		}
	}
	return out
}
