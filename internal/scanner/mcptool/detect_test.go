package mcptool

import "testing"

// mkFiles is a shared test helper used across mcptool tests.
func mkFiles(m map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range m {
		out[k] = []byte(v)
	}
	return out
}

func TestHasMCPDependency(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"go-mcp", map[string]string{"go.mod": "require github.com/mark3labs/mcp-go v0.1.0"}, true},
		{"ts-sdk", map[string]string{"package.json": `{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}`}, true},
		{"py-fastmcp", map[string]string{"requirements.txt": "fastmcp==2.0\n"}, true},
		{"none", map[string]string{"go.mod": "require github.com/spf13/cobra v1.0.0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasMCPDependency(mkFiles(c.files)); got != c.want {
				t.Fatalf("hasMCPDependency = %v, want %v", got, c.want)
			}
		})
	}
}
