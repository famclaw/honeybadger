// Package rulesdata provides the embedded rule YAML files.
package rulesdata

import "embed"

// FS holds the embedded rule YAML files.
//
//go:embed all:supplychain all:skillsafety
var FS embed.FS
