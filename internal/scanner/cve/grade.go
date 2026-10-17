package cve

import "github.com/famclaw/honeybadger/internal/scan"

func gradeSeverity(cvss, reason string, exploited bool, epss *scan.EPSS) (string, string) {
	if exploited {
		return scan.SevCritical, "actively_exploited_kev"
	}
	if epss != nil && epss.Percentile >= 0.9 {
		return scan.SevHigh, "high_epss_percentile"
	}
	return cvss, reason
}
