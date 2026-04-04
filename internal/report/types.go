package report

// Emitter writes scan events to output. Implementations: NDJSONEmitter, TextEmitter.
type Emitter interface {
	Emit(v any) error
	Close() error
}
