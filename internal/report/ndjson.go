package report

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/famclaw/honeybadger/internal/scan"
)

// NDJSONEmitter writes newline-delimited JSON to the given writer.
// Each call to Emit writes one JSON line per finding immediately (no buffering).
// A []scan.Finding argument writes one line per element.
type NDJSONEmitter struct {
	w   io.Writer
	enc *json.Encoder
	mu  sync.Mutex // protect concurrent writes
}

func NewNDJSONEmitter(w io.Writer) *NDJSONEmitter {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &NDJSONEmitter{w: w, enc: enc}
}

func (e *NDJSONEmitter) Emit(v any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if fs, ok := v.([]scan.Finding); ok {
		for _, f := range fs {
			if err := e.enc.Encode(f); err != nil {
				return err
			}
		}
		return nil
	}

	return e.enc.Encode(v) // json.Encoder.Encode appends \n automatically
}

func (e *NDJSONEmitter) Close() error {
	return nil // nothing to flush — each Emit writes immediately
}
