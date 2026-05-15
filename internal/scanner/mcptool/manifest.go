package mcptool

import (
	"encoding/json"
	"fmt"
)

// wireManifest matches the MCP tools/list response JSON.
type wireManifest struct {
	Tools []wireTool `json:"tools"`
}

type wireTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		Properties map[string]wireParam `json:"properties"`
		Required   []string             `json:"required"`
	} `json:"inputSchema"`
	Annotations *wireAnnotations `json:"annotations"`
	Digest      string           `json:"digest"` // optional, SEP-1766
}

type wireParam struct {
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Default     json.RawMessage   `json:"default"`
	Enum        []json.RawMessage `json:"enum"`
}

type wireAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint"`
	DestructiveHint *bool `json:"destructiveHint"`
	IdempotentHint  *bool `json:"idempotentHint"`
	OpenWorldHint   *bool `json:"openWorldHint"`
}

// parseManifest decodes MCP tools/list JSON into normalized ToolDefs.
func parseManifest(data []byte) ([]ToolDef, error) {
	var wm wireManifest
	if err := json.Unmarshal(data, &wm); err != nil {
		return nil, fmt.Errorf("parse tool manifest: %w", err)
	}
	tools := make([]ToolDef, 0, len(wm.Tools))
	for _, wt := range wm.Tools {
		td := ToolDef{Name: wt.Name, Description: wt.Description}
		if wt.Annotations != nil {
			td.Annotations = &Annotations{
				ReadOnlyHint:    wt.Annotations.ReadOnlyHint,
				DestructiveHint: wt.Annotations.DestructiveHint,
				IdempotentHint:  wt.Annotations.IdempotentHint,
				OpenWorldHint:   wt.Annotations.OpenWorldHint,
			}
		}
		for pname, wp := range wt.InputSchema.Properties {
			pd := ParamDef{
				Name: pname, Type: wp.Type,
				Title: wp.Title, Description: wp.Description,
			}
			if len(wp.Default) > 0 {
				pd.Default = string(wp.Default)
			}
			for _, e := range wp.Enum {
				pd.Enum = append(pd.Enum, string(e))
			}
			td.Params = append(td.Params, pd)
		}
		tools = append(tools, td)
	}
	return tools, nil
}
