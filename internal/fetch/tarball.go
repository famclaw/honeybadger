package fetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TarballFetcher downloads and extracts .tar.gz or .zip archives from URLs.
type TarballFetcher struct{}

// Fetch downloads an archive from the URL, extracts it, and reads files into a Repo.
func (t *TarballFetcher) Fetch(ctx context.Context, url string, opts FetchOptions) (*Repo, error) {
	// Download archive
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("tarball: creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tarball: downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("tarball: download %s returned status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("tarball: reading response body: %w", err)
	}

	files := make(map[string][]byte)

	if strings.HasSuffix(url, ".zip") {
		if err := extractZip(data, files, opts.SubPath); err != nil {
			return nil, fmt.Errorf("tarball: extracting zip: %w", err)
		}
	} else {
		// Assume .tar.gz / .tgz
		if err := extractTarGz(data, files, opts.SubPath); err != nil {
			return nil, fmt.Errorf("tarball: extracting tar.gz: %w", err)
		}
	}

	repo := &Repo{
		URL:       url,
		Platform:  "tarball",
		Files:     files,
		FetchedAt: time.Now(),
	}
	return repo, nil
}

// LocalFetcher reads files from a local directory.
type LocalFetcher struct{}

// Fetch walks a local directory and reads all text files into a Repo.
func (l *LocalFetcher) Fetch(ctx context.Context, path string, opts FetchOptions) (*Repo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("local: stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("local: %s is not a directory", path)
	}

	files := make(map[string][]byte)
	root := path
	if opts.SubPath != "" {
		root = filepath.Join(path, opts.SubPath)
	}

	err = filepath.Walk(root, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if info.IsDir() {
			// Skip .git directory
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if isBinaryExtension(fpath) {
			return nil
		}

		// Check first 512 bytes for null bytes (binary detection)
		f, err := os.Open(fpath)
		if err != nil {
			return nil // skip unreadable files
		}
		defer f.Close()

		header := make([]byte, 512)
		n, err := f.Read(header)
		if err != nil && err != io.EOF {
			return nil
		}
		if containsNullByte(header[:n]) {
			return nil // skip binary files
		}

		// Re-read the full file
		content, err := os.ReadFile(fpath)
		if err != nil {
			return nil
		}

		relPath, err := filepath.Rel(path, fpath)
		if err != nil {
			relPath = fpath
		}
		// Normalize to forward slashes
		relPath = filepath.ToSlash(relPath)
		files[relPath] = content
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local: walking directory: %w", err)
	}

	// Try to read HEAD SHA from .git
	sha := ""
	headFile := filepath.Join(path, ".git", "HEAD")
	if headData, err := os.ReadFile(headFile); err == nil {
		headStr := strings.TrimSpace(string(headData))
		if strings.HasPrefix(headStr, "ref: ") {
			refPath := strings.TrimPrefix(headStr, "ref: ")
			refFile := filepath.Join(path, ".git", refPath)
			if refData, err := os.ReadFile(refFile); err == nil {
				sha = strings.TrimSpace(string(refData))
			}
		} else {
			sha = headStr
		}
	}

	dirName := filepath.Base(path)
	repo := &Repo{
		URL:       path,
		Name:      dirName,
		Platform:  "local",
		SHA:       sha,
		Files:     files,
		FetchedAt: time.Now(),
	}
	return repo, nil
}

// extractTarGz extracts a .tar.gz archive into the files map.
func extractTarGz(data []byte, files map[string][]byte, subPath string) error {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		path := hdr.Name
		// Strip leading directory component (many archives have a top-level dir)
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = path[idx+1:]
		}

		if isBinaryExtension(path) {
			continue
		}
		if subPath != "" && !strings.HasPrefix(path, subPath) {
			continue
		}

		content, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("reading file %s: %w", path, err)
		}
		if !containsNullByte(content[:min(512, len(content))]) {
			files[path] = content
		}
	}
	return nil
}

// extractZip extracts a .zip archive into the files map.
func extractZip(data []byte, files map[string][]byte, subPath string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("creating zip reader: %w", err)
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}

		path := f.Name
		// Strip leading directory
		if idx := strings.Index(path, "/"); idx >= 0 {
			path = path[idx+1:]
		}

		if isBinaryExtension(path) {
			continue
		}
		if subPath != "" && !strings.HasPrefix(path, subPath) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		if !containsNullByte(content[:min(512, len(content))]) {
			files[path] = content
		}
	}
	return nil
}

// containsNullByte checks if a byte slice contains a null byte (binary indicator).
func containsNullByte(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

