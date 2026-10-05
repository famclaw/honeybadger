package scan

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseParanoia(t *testing.T) {
	tests := []struct {
		input   string
		want    ParanoiaLevel
		wantErr bool
	}{
		{"off", ParanoiaOff, false},
		{"minimal", ParanoiaMinimal, false},
		{"family", ParanoiaFamily, false},
		{"strict", ParanoiaStrict, false},
		{"paranoid", ParanoiaParanoid, false},
		{"", "", true},
		{"invalid", "", true},
		{"FAMILY", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseParanoia(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseParanoia(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseParanoia(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	tests := []struct {
		higher string
		lower  string
	}{
		{SevCritical, SevHigh},
		{SevHigh, SevMedium},
		{SevMedium, SevLow},
		{SevLow, SevInfo},
	}
	for _, tt := range tests {
		t.Run(tt.higher+">"+tt.lower, func(t *testing.T) {
			if SeverityRank(tt.higher) <= SeverityRank(tt.lower) {
				t.Errorf("SeverityRank(%q)=%d should be > SeverityRank(%q)=%d",
					tt.higher, SeverityRank(tt.higher), tt.lower, SeverityRank(tt.lower))
			}
		})
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	original := Finding{
		Type:      "finding",
		Severity:  SevHigh,
		Check:     "secrets",
		File:      "config.yaml",
		Line:      42,
		Message:   "Hardcoded API key found",
		Snippet:   "api_key: sk-1234****5678",
		Package:   "example-pkg",
		Version:   "1.2.3",
		ID:        "CVE-2024-1234",
		Summary:   "Test vulnerability",
		FixedIn:   "1.2.4",
		Ecosystem: "npm",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("Round-trip mismatch:\n  got:  %+v\n  want: %+v", decoded, original)
	}
}

func TestBlockThresholds(t *testing.T) {
	levels := []ParanoiaLevel{ParanoiaMinimal, ParanoiaFamily, ParanoiaStrict, ParanoiaParanoid}
	for _, level := range levels {
		t.Run(string(level), func(t *testing.T) {
			sev, ok := BlockThresholds[level]
			if !ok {
				t.Errorf("BlockThresholds missing entry for %q", level)
				return
			}
			if SeverityRank(sev) == 0 {
				t.Errorf("BlockThresholds[%q] = %q which has rank 0 (unknown severity)", level, sev)
			}
		})
	}

	if _, ok := BlockThresholds[ParanoiaOff]; ok {
		t.Error("BlockThresholds should not have an entry for ParanoiaOff")
	}
}

func TestOptionsHasToolFields(t *testing.T) {
	o := Options{ToolManifest: "m.json", ToolBaseline: "b.json"}
	if o.ToolManifest != "m.json" || o.ToolBaseline != "b.json" {
		t.Fatalf("ToolManifest/ToolBaseline not settable")
	}
}

func TestFindingJSONShapeFileRole(t *testing.T) {
	// (a) A classified finding carries a valid role in the JSON.
	classified := Finding{
		Type:     "finding",
		Severity: SevHigh,
		Check:    "secrets",
		File:     "main.go",
		FileRole: RoleCode,
		Message:  "test",
	}
	data, err := json.Marshal(classified)
	if err != nil {
		t.Fatalf("Marshal classified: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal classified: %v", err)
	}
	fr, ok := m["file_role"]
	if !ok {
		t.Fatal("classified finding: expected file_role key in JSON, got omitted")
	}
	if fr != "code" {
		t.Errorf("classified finding: file_role = %q, want %q", fr, "code")
	}

	// (b) An unclassified finding omits the file_role key entirely.
	unclassified := Finding{
		Type:     "finding",
		Severity: SevLow,
		Check:    "meta",
		File:     "doc.md",
		Message:  "unclassified",
	}
	data, err = json.Marshal(unclassified)
	if err != nil {
		t.Fatalf("Marshal unclassified: %v", err)
	}
	var m2 map[string]interface{}
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatalf("Unmarshal unclassified: %v", err)
	}
	if _, ok := m2["file_role"]; ok {
		t.Error("unclassified finding: file_role key present in JSON, expected omitted")
	}
}
