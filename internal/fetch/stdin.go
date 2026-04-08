package fetch

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// StdinFetcher reads scan content from an io.Reader (defaulting to os.Stdin)
// and wraps it in a synthetic single-file Repo.
type StdinFetcher struct {
	Reader   io.Reader // defaults to os.Stdin if nil
	Filename string    // defaults to "SKILL.md"
}

// Fetch reads all input into a single-file Repo. Input is capped at 10 MB.
func (f *StdinFetcher) Fetch(ctx context.Context, url string, opts FetchOptions) (*Repo, error) {
	const maxSize = 10 * 1024 * 1024
	reader := f.Reader
	if reader == nil {
		reader = os.Stdin
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(maxSize)+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("stdin input exceeds %d bytes", maxSize)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("stdin input is empty")
	}
	filename := f.Filename
	if filename == "" {
		filename = "SKILL.md"
	}
	return &Repo{
		URL:       "stdin",
		Name:      "stdin",
		Platform:  "stdin",
		Files:     map[string][]byte{filename: data},
		FetchedAt: time.Now(),
	}, nil
}
