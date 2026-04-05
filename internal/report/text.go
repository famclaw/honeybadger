package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// TextEmitter writes human-readable output with severity markers.
type TextEmitter struct {
	w  io.Writer
	mu sync.Mutex
}

// NewTextEmitter creates a TextEmitter that writes to w.
func NewTextEmitter(w io.Writer) *TextEmitter {
	return &TextEmitter{w: w}
}

func (e *TextEmitter) Emit(v any) error {
	// Marshal to map to inspect the "type" field generically.
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("text emit marshal: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Not a JSON object — print as info.
		return e.writef("[info] %s\n", string(raw))
	}

	typ, _ := m["type"].(string)
	switch typ {
	case "progress":
		msg, _ := m["message"].(string)
		return e.writef("[*] %s\n", msg)

	case "finding", "cve":
		sev, _ := m["severity"].(string)
		file, _ := m["file"].(string)
		line, _ := m["line"].(float64)
		msg, _ := m["message"].(string)
		if file != "" && int(line) > 0 {
			return e.writef("[%s] %s:%d — %s\n", sev, file, int(line), msg)
		} else if file != "" {
			return e.writef("[%s] %s — %s\n", sev, file, msg)
		}
		return e.writef("[%s] %s\n", sev, msg)

	case "result":
		return e.writeVerdict(m)

	case "sandbox":
		avail, _ := m["available"].(bool)
		reason, _ := m["reason"].(string)
		ep, _ := m["effective_paranoia"].(string)
		if avail {
			return e.writef("[sandbox] Available (%s), effective paranoia: %s\n", reason, ep)
		}
		return e.writef("[sandbox] Unavailable (%s), effective paranoia: %s\n", reason, ep)

	case "health":
		stars, _ := m["stars"].(float64)
		contribs, _ := m["contributors"].(float64)
		age, _ := m["age_days"].(float64)
		license, _ := m["has_license"].(bool)
		licStr := "no"
		if license {
			licStr = "yes"
		}
		return e.writef("[health] Stars: %d | Contributors: %d | Age: %d days | License: %s\n",
			int(stars), int(contribs), int(age), licStr)

	default:
		return e.writef("[info] %s\n", string(raw))
	}
}

func (e *TextEmitter) writeVerdict(m map[string]any) error {
	verdict, _ := m["verdict"].(string)
	reasoning, _ := m["reasoning"].(string)

	counts, _ := m["finding_counts"].(map[string]any)
	critical, _ := counts["critical"].(float64)
	high, _ := counts["high"].(float64)
	medium, _ := counts["medium"].(float64)
	low, _ := counts["low"].(float64)

	cveCount, _ := m["cve_count"].(float64)
	cveMaxSev := "none"
	if s, ok := m["cve_max_severity"].(string); ok && s != "" {
		cveMaxSev = s
	}

	durationMs, _ := m["duration_ms"].(float64)

	bar := "══════════════════════════════════════"
	return e.writef("%s\nVERDICT: %s\n%s\n%s\n\nFindings: %d critical, %d high, %d medium, %d low\nCVEs: %d (max severity: %s)\nDuration: %dms\n%s\n",
		bar, verdict, bar,
		reasoning,
		int(critical), int(high), int(medium), int(low),
		int(cveCount), cveMaxSev,
		int(durationMs),
		bar,
	)
}

func (e *TextEmitter) writef(format string, args ...any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := fmt.Fprintf(e.w, format, args...)
	return err
}

func (e *TextEmitter) Close() error {
	return nil
}
