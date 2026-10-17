package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/famclaw/honeybadger/internal/scan"
)

const (
	kevURL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL       = "https://api.first.org/data/v1/epss"
	kevTTL        = 6 * time.Hour
	feedTimeout   = 10 * time.Second
	epssBatchSize = 100
)

var kevEndpoint, epssEndpoint = kevURL, epssURL
var kevCache struct {
	sync.Mutex
	expires time.Time
	entries map[string]bool
}

type exploitationInfo struct {
	exploited bool
	epss      *scan.EPSS
}
type kevResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}
type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		Score      string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

func fetchKEV(ctx context.Context) (map[string]bool, error) {
	kevCache.Lock()
	defer kevCache.Unlock()
	if time.Now().Before(kevCache.expires) && kevCache.entries != nil {
		return kevCache.entries, nil
	}
	var feed kevResponse
	if err := getJSON(ctx, kevEndpoint, &feed); err != nil {
		return nil, fmt.Errorf("CISA KEV feed unavailable: %w", err)
	}
	entries := make(map[string]bool, len(feed.Vulnerabilities))
	for _, vuln := range feed.Vulnerabilities {
		if vuln.CVEID != "" {
			entries[vuln.CVEID] = true
		}
	}
	kevCache.entries, kevCache.expires = entries, time.Now().Add(kevTTL)
	return entries, nil
}

func lookupExploitation(ctx context.Context, ids []string) (map[string]exploitationInfo, []string) {
	unique := make(map[string]bool)
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			unique[id] = true
		}
	}
	results := make(map[string]exploitationInfo, len(unique))
	if len(unique) == 0 {
		return results, nil
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	// Stable ordering makes batching reproducible.
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if ordered[j] < ordered[i] {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	var errors []string
	kev, err := fetchKEV(ctx)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		for id := range unique {
			if kev[id] {
				info := results[id]
				info.exploited = true
				results[id] = info
			}
		}
	}
	for start := 0; start < len(ordered); start += epssBatchSize {
		end := start + epssBatchSize
		if end > len(ordered) {
			end = len(ordered)
		}
		u := epssEndpoint + "?cve=" + url.QueryEscape(strings.Join(ordered[start:end], ","))
		var feed epssResponse
		if err := getJSON(ctx, u, &feed); err != nil {
			errors = append(errors, fmt.Sprintf("FIRST EPSS feed unavailable for batch %d: %v", start/epssBatchSize+1, err))
			continue
		}
		for _, row := range feed.Data {
			score, scoreErr := strconv.ParseFloat(row.Score, 64)
			percentile, percentileErr := strconv.ParseFloat(row.Percentile, 64)
			if scoreErr != nil || percentileErr != nil {
				errors = append(errors, fmt.Sprintf("FIRST EPSS feed returned invalid numeric data for %s", row.CVE))
				continue
			}
			value := scan.EPSS{Score: score, Percentile: percentile}
			info := results[row.CVE]
			info.epss = &value
			results[row.CVE] = info
		}
	}
	return results, errors
}

func getJSON(ctx context.Context, endpoint string, target any) error {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		client := &http.Client{Timeout: feedTimeout}
		resp, err := client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				err = json.NewDecoder(resp.Body).Decode(target)
			} else {
				err = fmt.Errorf("HTTP status %d", resp.StatusCode)
			}
			resp.Body.Close()
		}
		if err == nil {
			return nil
		}
		last = err
		if attempt == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(150 * time.Millisecond):
			}
		}
	}
	return last
}
