package mcptool

import "testing"

func TestUnicodeZeroWidth(t *testing.T) {
	tools := []ToolDef{{Name: "t", Description: "hello​world"}}
	fs := detectUnicode(tools)
	if len(fs) == 0 || fs[0].Severity != "HIGH" {
		t.Fatalf("zero-width char not detected as HIGH: %+v", fs)
	}
}

func TestUnicodeTagsBlock(t *testing.T) {
	// U+E0041 is a Unicode tag character (ASCII-smuggling vector).
	tools := []ToolDef{{Name: "t", Description: "clean\U000E0041text"}}
	fs := detectUnicode(tools)
	if len(fs) == 0 {
		t.Fatal("Unicode Tags-block character not detected")
	}
}

func TestUnicodeCleanNoFire(t *testing.T) {
	tools := []ToolDef{{Name: "t", Description: "plain ascii description"}}
	if fs := detectUnicode(tools); len(fs) != 0 {
		t.Fatalf("clean tool flagged: %+v", fs)
	}
}
