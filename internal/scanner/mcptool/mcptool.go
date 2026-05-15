package mcptool

import (
	"context"
	"fmt"
	"os"

	"github.com/famclaw/honeybadger/internal/fetch"
	"github.com/famclaw/honeybadger/internal/scan"
)

// Run implements scan.ScanFunc for the mcptool scanner. It loads MCP tool
// definitions from the --tool-manifest file when supplied, otherwise falls
// back to heuristic source extraction, then runs the detections.
func Run(ctx context.Context, repo *fetch.Repo, opts scan.Options, out chan<- scan.Finding, errs chan<- scan.RuntimeError) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	manifestMode := opts.ToolManifest != ""
	var tools []ToolDef

	if manifestMode {
		data, err := os.ReadFile(opts.ToolManifest)
		if err != nil {
			errs <- scan.NewRuntimeError("mcptool", fmt.Sprintf("read --tool-manifest: %v", err))
			return
		}
		parsed, err := parseManifest(data)
		if err != nil {
			errs <- scan.NewRuntimeError("mcptool", err.Error())
			return
		}
		tools = parsed
	} else {
		tools = extractFromSource(repo)
	}

	// Coverage gap: an MCP server whose tools could not be analyzed.
	if len(tools) == 0 {
		if !manifestMode && hasMCPDependency(repo.Files) {
			out <- scan.Finding{
				Type:     "finding",
				Check:    "mcptool",
				Severity: scan.SevMedium,
				RuleID:   "mcp-no-tools-found",
				Message: "MCP server dependency detected but no tool definitions could be " +
					"analyzed -- supply --tool-manifest. Tools may be generated at runtime.",
			}
		}
		return
	}

	// Detections are wired in Task 14.
	runDetections(ctx, repo, opts, tools, manifestMode, out, errs)
}

// runDetections dispatches every detection. Detections are added task-by-task;
// until Task 14 this is a no-op stub.
func runDetections(ctx context.Context, repo *fetch.Repo, opts scan.Options, tools []ToolDef, manifestMode bool, out chan<- scan.Finding, errs chan<- scan.RuntimeError) {
}
