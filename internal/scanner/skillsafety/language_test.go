package skillsafety

import "testing"

func TestDetectLanguages(t *testing.T) {
	tests := []struct {
		name              string
		text              string
		wantPrimary       string
		wantAllContains   string
		wantUnexpectedLen int
	}{
		{
			name:              "pure Latin",
			text:              "This is a simple English text with only Latin characters and nothing else at all.",
			wantPrimary:       "Latin",
			wantAllContains:   "Latin",
			wantUnexpectedLen: 0,
		},
		{
			name: "mixed Latin and Cyrillic",
			// Need >80% Latin and >20 Cyrillic chars to trigger unexpected.
			// ~120 Latin chars + 25 Cyrillic = ~145 total, 120/145 ≈ 83% > 80%.
			text:              "This is a long English sentence that contains many Latin characters to establish a dominant script and ensure we are well above eighty percent. " + "абвгдеёжзийклмнопрстуфхцшщ",
			wantPrimary:       "Latin",
			wantAllContains:   "Cyrillic",
			wantUnexpectedLen: 1,
		},
		{
			name:              "CJK primary not unexpected",
			text:              "这是一段很长的中文文本。这段文本的主要目的是为了测试语言检测功能是否能够正确地识别中文作为主要语言。我们需要足够多的汉字来确保检测结果准确无误。",
			wantPrimary:       "Han",
			wantAllContains:   "Han",
			wantUnexpectedLen: 0,
		},
		{
			name:              "empty text",
			text:              "",
			wantPrimary:       "",
			wantAllContains:   "",
			wantUnexpectedLen: 0,
		},
		{
			name:              "only digits and punctuation",
			text:              "12345 !@#$%",
			wantPrimary:       "",
			wantAllContains:   "",
			wantUnexpectedLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary, all, unexpected := DetectLanguages(tt.text)

			if primary != tt.wantPrimary {
				t.Errorf("primary = %q, want %q", primary, tt.wantPrimary)
			}

			if tt.wantAllContains != "" {
				found := false
				for _, a := range all {
					if a == tt.wantAllContains {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("all = %v, expected to contain %q", all, tt.wantAllContains)
				}
			}

			if len(unexpected) != tt.wantUnexpectedLen {
				t.Errorf("unexpected = %v (len %d), want len %d", unexpected, len(unexpected), tt.wantUnexpectedLen)
			}
		})
	}
}
