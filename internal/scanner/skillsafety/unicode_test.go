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

func TestDetectHomoglyphs(t *testing.T) {
	tests := []struct {
		name string
		text string
		want int // expected number of suspicious words
	}{
		{"clean_english", "This is a normal English sentence about weather APIs.", 0},
		{"clean_russian", "Это обычное русское предложение о погодных данных.", 0},
		{"clean_chinese", "这是一个关于天气的正常中文句子。", 0},
		// Cyrillic 'а' (U+0430) in Latin word
		{"cyrillic_a_in_paypal", "Visit p\u0430ypal.com to complete payment", 1},
		// Greek 'ο' (U+03BF) in Latin word
		{"greek_o_in_google", "Search on g\u03BF\u03BFgle.com for results", 1},
		{"multiple_homoglyphs", "Try p\u0430ypal and g\u03BF\u03BFgle today", 2},
		// Short words should be ignored
		{"short_word_ignored", "a\u0430 b\u0431", 0},
		{"three_char_mixed", "ab\u0430 is flagged", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectHomoglyphs(tt.text)
			if len(got) != tt.want {
				t.Errorf("DetectHomoglyphs() = %v (len %d), want len %d", got, len(got), tt.want)
			}
		})
	}
}
