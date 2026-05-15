package mcptool

import "testing"

func TestTextFields(t *testing.T) {
	td := ToolDef{
		Name:        "t",
		Description: "tool desc",
		Params: []ParamDef{{
			Name: "p", Description: "param desc", Title: "Param",
			Default: `"def"`, Enum: []string{`"a"`, `"b"`},
		}},
	}
	fields := textFields(td)
	got := map[string]string{}
	for _, f := range fields {
		got[f.Label] = f.Text
	}
	if got["description"] != "tool desc" {
		t.Fatalf("missing tool description: %v", got)
	}
	if got["param[p].description"] != "param desc" {
		t.Fatalf("missing param description: %v", got)
	}
	if got["param[p].title"] != "Param" {
		t.Fatalf("missing param title: %v", got)
	}
	if got["param[p].default"] != `"def"` {
		t.Fatalf("missing param default: %v", got)
	}
	if got["param[p].enum[1]"] != `"b"` {
		t.Fatalf("missing param enum: %v", got)
	}
}
