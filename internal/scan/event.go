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
// security finding. RuntimeErrors feed into check-status tracking:
// a scanner that panics or fails causes its check to be marked FAIL,
// which can downgrade an otherwise clean verdict to INCOMPLETE.
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
