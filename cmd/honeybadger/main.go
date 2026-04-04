package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Version is injected at build time via ldflags.
var Version = "dev"

func main() {
	// Read environment variables
	llmEndpoint := envOrDefault("HONEYBADGER_LLM", "")
	llmKey := envOrDefault("HONEYBADGER_LLM_KEY", "")
	llmModel := envOrDefault("HONEYBADGER_LLM_MODEL", "")
	githubToken := envOrDefault("GITHUB_TOKEN", "")
	gitlabToken := envOrDefault("GITLAB_TOKEN", "")

	// Define flags
	paranoia := flag.String("paranoia", "family", "paranoia level: off|minimal|family|strict|paranoid")
	format := flag.String("format", "ndjson", "output format: ndjson|text")
	llm := flag.String("llm", llmEndpoint, "LLM endpoint override")
	db := flag.String("db", "", "SQLite path for audit trail")
	installedSHA := flag.String("installed-sha", "", "installed commit SHA")
	installedToolHash := flag.String("installed-tool-hash", "", "installed tool hash")
	force := flag.Bool("force", false, "force scan even if already audited")
	offline := flag.Bool("offline", false, "offline mode — skip network checks")
	path := flag.String("path", "", "subdirectory within repo")
	// --mcp-server and --version are handled before flag.Parse (see below)

	// Extract subcommand before parsing flags.
	// This allows: honeybadger scan <url> --paranoia strict
	args := os.Args[1:]
	subcommand := ""
	var repoURL string
	var remaining []string

	for i, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Println("honeybadger", Version)
			os.Exit(0)
		}
		if arg == "--mcp-server" || arg == "-mcp-server" {
			if err := serveMCP(); err != nil {
				fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if arg == "scan" && subcommand == "" {
			subcommand = "scan"
			// Next non-flag arg is the repo URL
			for j := i + 1; j < len(args); j++ {
				if !strings.HasPrefix(args[j], "-") && repoURL == "" {
					repoURL = args[j]
				} else {
					remaining = append(remaining, args[j])
				}
			}
			break
		}
	}

	if subcommand != "scan" {
		fmt.Fprintln(os.Stderr, "usage: honeybadger scan <repo-url> [flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if repoURL == "" {
		fmt.Fprintln(os.Stderr, "error: scan requires a <repo-url> argument")
		os.Exit(1)
	}

	// Parse remaining flags after extracting subcommand and URL
	if err := flag.CommandLine.Parse(remaining); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Suppress unused variable warnings by referencing all values
	_ = llmKey
	_ = llmModel
	_ = githubToken
	_ = gitlabToken

	if err := run(repoURL, *paranoia, *format, *llm, *db, *installedSHA, *installedToolHash, *force, *offline, *path); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(repoURL, paranoia, format, llm, db, installedSHA, installedToolHash string, force, offline bool, path string) error {
	fmt.Println("not implemented")
	return nil
}

func serveMCP() error {
	fmt.Println("not implemented")
	return nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
