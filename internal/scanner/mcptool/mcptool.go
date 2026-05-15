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

// runDetections dispatches every detection against the loaded tools.
func runDetections(ctx context.Context, repo *fetch.Repo, opts scan.Options, tools []ToolDef, manifestMode bool, out chan<- scan.Finding, errs chan<- scan.RuntimeError) {
	emit := func(fs []scan.Finding) {
		for _, f := range fs {
			select {
			case <-ctx.Done():
				return
			case out <- f:
			}
		}
	}

	// Detection 1 — injection (works in both modes).
	injFindings, injHitNames := detectInjectionWithHits(tools, opts.Rules)
	emit(injFindings)

	// Detection 2 — unicode (works in both modes).
	emit(detectUnicode(tools))

	if !manifestMode {
		// Degraded mode: structural detections need the manifest.
		out <- scan.Finding{
			Type:     "finding",
			Check:    "mcptool",
			Severity: scan.SevInfo,
			RuleID:   "mcp-source-only",
			Message: "Tool definitions were extracted heuristically from source; " +
				"shadowing, capability, and rug-pull checks were skipped. Supply " +
				"--tool-manifest for full analysis.",
		}
		return
	}

	// Enrich manifest tools with source-file locations (best-effort) so the
	// capability detector's source-confirmation layer can run.
	select {
	case <-ctx.Done():
		return
	default:
	}
	if srcTools := extractFromSource(repo); len(srcTools) > 0 {
		srcFile := map[string]string{}
		for _, st := range srcTools {
			srcFile[st.Name] = st.SourceFile
		}
		for i := range tools {
			if f, ok := srcFile[tools[i].Name]; ok {
				tools[i].SourceFile = f
			}
		}
	}

	// Detection 3 — shadowing. Use the injection hit set returned directly by
	// detectInjectionWithHits — no message-string parsing required.
	select {
	case <-ctx.Done():
		return
	default:
	}
	emit(detectShadowing(tools, injHitNames))

	// Detection 4 — capability mismatch (layers 1-4).
	select {
	case <-ctx.Done():
		return
	default:
	}
	emit(detectCapability(tools, repo.Files))

	// Detection 5 — rug-pull (only when a baseline is supplied).
	if opts.ToolBaseline != "" {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, err := os.ReadFile(opts.ToolBaseline)
		if err != nil {
			errs <- scan.NewRuntimeError("mcptool", fmt.Sprintf("read --tool-baseline: %v", err))
			return
		}
		baseline, err := parseManifest(data)
		if err != nil {
			errs <- scan.NewRuntimeError("mcptool", fmt.Sprintf("parse --tool-baseline: %v", err))
			return
		}
		emit(detectRugPull(tools, baseline))
	}
}
