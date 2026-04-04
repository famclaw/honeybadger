package report

import (
	"encoding/json"
	"io"
	"sync"
)

// NDJSONEmitter writes newline-delimited JSON to the given writer.
// Each call to Emit writes one JSON line immediately (no buffering).
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
	return e.enc.Encode(v) // json.Encoder.Encode appends \n automatically
}

func (e *NDJSONEmitter) Close() error {
	return nil // nothing to flush — each Emit writes immediately
}
