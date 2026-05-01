package scan

// Event is anything RunAll can emit on its output channel.
// Implementations: Finding, RuntimeError.
type Event interface {
	isEvent()
}

func (Finding) isEvent()      {}
func (RuntimeError) isEvent() {}

// RuntimeError reports a scanner failure (panic, external service failure,
// configuration load error, etc.) that is operationally distinct from a
// security finding. RuntimeErrors do not affect verdict computation —
// a panicking scanner cannot flip a clean repo to FAIL.
type RuntimeError struct {
	Type    string `json:"type"` // always "runtime_error"
	Scanner string `json:"scanner"`
	Message string `json:"message"`
	At      string `json:"at,omitempty"`
}

// NewRuntimeError constructs a RuntimeError with the type tag set.
func NewRuntimeError(scanner, message string) RuntimeError {
	return RuntimeError{
		Type:    "runtime_error",
		Scanner: scanner,
		Message: message,
	}
}
