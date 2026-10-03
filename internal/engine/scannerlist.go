package engine

import (
	"github.com/famclaw/honeybadger/internal/scan"
	"github.com/famclaw/honeybadger/internal/scanner/attestation"
	"github.com/famclaw/honeybadger/internal/scanner/capability"
	"github.com/famclaw/honeybadger/internal/scanner/cve"
	"github.com/famclaw/honeybadger/internal/scanner/mcptool"
	"github.com/famclaw/honeybadger/internal/scanner/meta"
	"github.com/famclaw/honeybadger/internal/scanner/secrets"
	"github.com/famclaw/honeybadger/internal/scanner/skillsafety"
	"github.com/famclaw/honeybadger/internal/scanner/supplychain"
)

// namedScanner is a helper type that associates a scanner name with its scanning function.
type namedScanner struct {
	Name  string
	Run   scan.ScanFunc
}

// scannersFor returns the scanner set for a paranoia level. It is the single
// source of truth; both BuildScannerList and BuildScannerNames derive from it.
func scannersFor(opts scan.Options) []namedScanner {
	switch opts.Paranoia {
	case scan.ParanoiaOff:
		return nil
	case scan.ParanoiaMinimal:
		return []namedScanner{{"secrets", secrets.Run}, {"cve", cve.Run}}
	case scan.ParanoiaFamily:
		return []namedScanner{
			{"secrets", secrets.Run}, {"cve", cve.Run},
			{"supplychain", supplychain.Run}, {"meta", meta.Run},
			{"capability", capability.Run}, {"skillsafety", skillsafety.Run},
			{"mcptool", mcptool.Run},
		}
	case scan.ParanoiaStrict, scan.ParanoiaParanoid:
		return []namedScanner{
			{"secrets", secrets.Run}, {"cve", cve.Run},
			{"supplychain", supplychain.Run}, {"meta", meta.Run},
			{"capability", capability.Run}, {"skillsafety", skillsafety.Run},
			{"attestation", attestation.Run}, {"mcptool", mcptool.Run},
		}
	default:
		// Default to family
		return []namedScanner{
			{"secrets", secrets.Run}, {"cve", cve.Run},
			{"supplychain", supplychain.Run}, {"meta", meta.Run},
			{"capability", capability.Run}, {"skillsafety", skillsafety.Run},
			{"mcptool", mcptool.Run},
		}
	}
}