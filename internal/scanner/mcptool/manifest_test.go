package mcptool

import (
	"testing"
)

func TestParseManifest(t *testing.T) {
	js := []byte(`{"tools":[
		{"name":"read_file","description":"Read a file",
		 "inputSchema":{"properties":{"path":{"type":"string","description":"file path"}}},
		 "annotations":{"readOnlyHint":true}}
	]}`)
	tools, err := parseManifest(js)
	if err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("want 1 tool, got %d", len(tools))
	}
	tl := tools[0]
	if tl.Name != "read_file" || tl.Description != "Read a file" {
		t.Fatalf("bad tool: %+v", tl)
	}
	if len(tl.Params) != 1 || tl.Params[0].Name != "path" || tl.Params[0].Description != "file path" {
		t.Fatalf("bad params: %+v", tl.Params)
	}
	if tl.Annotations == nil || tl.Annotations.ReadOnlyHint == nil || !*tl.Annotations.ReadOnlyHint {
		t.Fatalf("readOnlyHint not parsed: %+v", tl.Annotations)
	}
}

func TestParseManifestInvalid(t *testing.T) {
	if _, err := parseManifest([]byte(`not json`)); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// TestParseManifestParamsSorted verifies that params are returned in
// deterministic alphabetical order regardless of JSON map iteration order.
func TestParseManifestParamsSorted(t *testing.T) {
	// JSON objects with multiple keys — Go maps iterate in random order.
	js := []byte(`{"tools":[{
		"name":"multi",
		"description":"Multi-param tool",
		"inputSchema":{"properties":{
			"zebra":{"type":"string","description":"last"},
			"alpha":{"type":"string","description":"first"},
			"middle":{"type":"string","description":"mid"}
		}}
	}]}`)
	tools, err := parseManifest(js)
	if err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("want 1 tool, got %d", len(tools))
	}
	params := tools[0].Params
	if len(params) != 3 {
		t.Fatalf("want 3 params, got %d: %+v", len(params), params)
	}
	// Must be alpha, middle, zebra.
	want := []string{"alpha", "middle", "zebra"}
	for i, p := range params {
		if p.Name != want[i] {
			t.Fatalf("params[%d].Name = %q, want %q (not sorted): %+v", i, p.Name, want[i], params)
		}
	}
}
