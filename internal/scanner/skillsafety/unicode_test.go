package skillsafety

import "testing"

func TestCountZeroWidth(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{
			name: "clean input",
			in:   "Hello World",
			want: 0,
		},
		{
			name: "single zero-width space",
			in:   "Hello\u200BWorld",
			want: 1,
		},
		{
			name: "multiple invisible chars",
			in:   "\u200BHello\u200CWorld\u200D!\uFEFF\u00AD",
			want: 5,
		},
		{
			name: "empty string",
			in:   "",
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CountZeroWidth(tt.in)
			if got != tt.want {
				t.Errorf("CountZeroWidth() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCountRTLOverrides(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{
			name: "clean input",
			in:   "Hello World",
			want: 0,
		},
		{
			name: "single RTL override",
			in:   "Hello\u202EWorld",
			want: 1,
		},
		{
			name: "multiple directional chars",
			in:   "\u200EHello\u200FWorld\u202A!\u202B\u202C",
			want: 5,
		},
		{
			name: "empty string",
			in:   "",
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CountRTLOverrides(tt.in)
			if got != tt.want {
				t.Errorf("CountRTLOverrides() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExtractHTMLComments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{
			name: "no comments",
			in:   "Hello World",
			want: 0,
		},
		{
			name: "single comment",
			in:   "Hello <!-- secret --> World",
			want: 1,
		},
		{
			name: "multiple comments",
			in:   "<!-- one --> text <!-- two --> more <!-- three -->",
			want: 3,
		},
		{
			name: "multiline comment",
			in:   "Hello <!--\nhidden\ntext\n--> World",
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractHTMLComments(tt.in)
			if len(got) != tt.want {
				t.Errorf("ExtractHTMLComments() returned %d comments, want %d", len(got), tt.want)
			}
		})
	}
}
