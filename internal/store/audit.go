package store

import (
	"encoding/json"
	"fmt"
	"os"
)

// WriteAudit appends a JSON line to the audit file at path.
// This is a lightweight approach compatible with future SQLite integration.
func WriteAudit(path string, result any) (retErr error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening audit file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing audit file: %w", cerr)
		}
	}()
	if err := json.NewEncoder(f).Encode(result); err != nil {
		return fmt.Errorf("encoding audit record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing audit file: %w", err)
	}
	return nil
}
