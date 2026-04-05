package store

import (
	"encoding/json"
	"fmt"
	"os"
)

// WriteAudit appends a JSON line to the audit file at path.
// This is a lightweight approach compatible with future SQLite integration.
func WriteAudit(path string, result map[string]any) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening audit file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(result)
}
