package cve

import "github.com/famclaw/honeybadger/internal/scan"

// gradeSeverity combines a CVSS-derived severity with exploitation intel.
//
// Rules:
//   - KEV (actively exploited) escalates to CRITICAL.
//   - A high EPSS percentile (>= 0.9) is enrichment: it labels the finding
//     "high_epss_percentile" and may raise severity, but it NEVER lowers a
//     CVSS-derived severity. A CRITICAL CVSS with high EPSS stays CRITICAL;
//     returning SevHigh unconditionally silently downgraded CRITICAL
//     findings whenever KEV was absent.
//   - With no intel, the CVSS severity and reason pass through unchanged.
func gradeSeverity(cvss, reason string, exploited bool, epss *scan.EPSS) (string, string) {
	if exploited {
		return scan.SevCritical, "actively_exploited_kev"
	}
	if epss != nil && epss.Percentile >= 0.9 {
		severity := scan.SevHigh
		if scan.SeverityRank(cvss) > scan.SeverityRank(severity) {
			severity = cvss
		}
		if reason == "" {
			return severity, "high_epss_percentile"
		}
		// Preserve an existing reason marker (e.g. severity_unknown) and add
		// the EPSS label to it rather than replacing it.
		return severity, reason + "+high_epss_percentile"
	}
	return cvss, reason
}
