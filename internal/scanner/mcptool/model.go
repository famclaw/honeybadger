// Package mcptool statically analyzes MCP tool definitions for poisoning,
// cross-tool shadowing, capability mismatch, and rug-pull drift.
package mcptool

// ToolDef is the normalized representation produced by both ingestion paths.
type ToolDef struct {
	Name        string
	Description string
	Params      []ParamDef
	Annotations *Annotations // nil when the tool declares none
	SourceFile  string       // set by source extraction; "" for manifest input
	HandlerName string       // set by source extraction when the handler symbol is known
}

// ParamDef is one input-schema parameter.
type ParamDef struct {
	Name        string
	Description string
	Title       string
	Type        string
	Default     string   // stringified
	Enum        []string // stringified enum values
}

// Annotations mirrors the MCP tool annotations object. Pointer fields
// distinguish "absent" from "false".
type Annotations struct {
	ReadOnlyHint    *bool
	DestructiveHint *bool
	IdempotentHint  *bool
	OpenWorldHint   *bool
}
