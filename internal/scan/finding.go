package scan

import "fmt"

// Severity levels
const (
	SevCritical = "CRITICAL"
	SevHigh     = "HIGH"
	SevMedium   = "MEDIUM"
	SevLow      = "LOW"
	SevInfo     = "INFO"
	SevError    = "ERROR" // for runner panics
)

// Finding matches the NDJSON output spec.
type Finding struct {
	Type      string `json:"type"`                // "finding" or "cve"
	Severity  string `json:"severity"`
	Check     string `json:"check"`               // scanner name: secrets, cve, supplychain, meta, attestation, network
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Message   string `json:"message"`
	Snippet   string `json:"snippet,omitempty"`
	Host      string `json:"host,omitempty"`
	Package   string `json:"package,omitempty"`   // for CVE findings
	Version   string `json:"version,omitempty"`
	ID        string `json:"id,omitempty"`        // CVE ID
	Summary   string `json:"summary,omitempty"`
	FixedIn   string `json:"fixed_in,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// ParanoiaLevel controls which scanners run and how aggressively.
type ParanoiaLevel string

const (
	ParanoiaOff      ParanoiaLevel = "off"
	ParanoiaMinimal  ParanoiaLevel = "minimal"
	ParanoiaFamily   ParanoiaLevel = "family"
	ParanoiaStrict   ParanoiaLevel = "strict"
	ParanoiaParanoid ParanoiaLevel = "paranoid"
)

// ParseParanoia parses a string to ParanoiaLevel, returns error for invalid values.
func ParseParanoia(s string) (ParanoiaLevel, error) {
	switch s {
	case "off":
		return ParanoiaOff, nil
	case "minimal":
		return ParanoiaMinimal, nil
	case "family":
		return ParanoiaFamily, nil
	case "strict":
		return ParanoiaStrict, nil
	case "paranoid":
		return ParanoiaParanoid, nil
	default:
		return "", fmt.Errorf("invalid paranoia level: %q (valid: off, minimal, family, strict, paranoid)", s)
	}
}

// BlockThresholds maps paranoia level to minimum severity that blocks installation.
var BlockThresholds = map[ParanoiaLevel]string{
	ParanoiaMinimal:  SevCritical,
	ParanoiaFamily:   SevHigh,
	ParanoiaStrict:   SevMedium,
	ParanoiaParanoid: SevLow,
}

// SeverityRank returns numeric rank for comparison (higher = more severe).
func SeverityRank(sev string) int {
	switch sev {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	case SevError:
		return 6
	default:
		return 0
	}
}

// Options holds configuration for a scan run.
type Options struct {
	Paranoia          ParanoiaLevel
	Format            string // "ndjson" or "text"
	LLMEndpoint       string
	LLMKey            string
	LLMModel          string
	DBPath            string
	InstalledSHA      string
	InstalledToolHash string
	Force             bool
	Offline           bool
	RepoPath          string // subdirectory within repo
	GithubToken       string
	GitlabToken       string
}
