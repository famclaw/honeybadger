package fetch

import (
	"context"
	"strings"
	"testing"
)

func TestStdinFetcher(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		filename string
		wantFile string
		wantErr  string
	}{
		{
			name:     "normal input",
			input:    "# My Skill\nDoes things.",
			wantFile: "SKILL.md",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "empty",
		},
		{
			name:     "custom filename",
			input:    "content",
			filename: "custom.yaml",
			wantFile: "custom.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &StdinFetcher{
				Reader:   strings.NewReader(tt.input),
				Filename: tt.filename,
			}

			repo, err := f.Fetch(context.Background(), "-", FetchOptions{})
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if repo.Platform != "stdin" {
				t.Errorf("Platform = %q, want %q", repo.Platform, "stdin")
			}
			if repo.Name != "stdin" {
				t.Errorf("Name = %q, want %q", repo.Name, "stdin")
			}
			if _, ok := repo.Files[tt.wantFile]; !ok {
				t.Errorf("Files missing %q, got keys: %v", tt.wantFile, fileKeys(repo.Files))
			}
			if string(repo.Files[tt.wantFile]) != tt.input {
				t.Errorf("file content = %q, want %q", string(repo.Files[tt.wantFile]), tt.input)
			}
		})
	}
}

func TestStdinFetcherOversized(t *testing.T) {
	// Create input just over 10 MB
	big := strings.Repeat("x", 10*1024*1024+1)
	f := &StdinFetcher{
		Reader: strings.NewReader(big),
	}

	_, err := f.Fetch(context.Background(), "-", FetchOptions{})
	if err == nil {
		t.Fatal("expected error for oversized input, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error %q does not mention size limit", err.Error())
	}
}
