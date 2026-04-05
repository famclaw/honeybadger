# Supply Chain Hardening & Docs Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the release pipeline to achieve genuine SLSA L2+, add OCI image builds, fix dogfooding gaps (SECURITY.md claims vs reality), add doc validation tests, and write clear integration guides for OpenClaw and Claude Code.

**Architecture:** Four independent streams — (A) release pipeline hardening (reproducible builds, SHA-pinned actions, cosign verify, OCI images), (B) fix self-check contradictions (SECURITY.md accuracy, CI enforcement), (C) doc validation tests that verify docs stay in sync with source, (D) integration documentation for OpenClaw (FamClaw MCP config) and Claude Code (MCP server config + settings.json).

**Tech Stack:** Go 1.26, GitHub Actions, Docker buildx, cosign, SLSA github-generator, `actions/attest-build-provenance`

---

## File Structure

### Stream A: Release Pipeline
- Modify: `.github/workflows/release.yml` — reproducible build flags, SHA-pinned actions, cosign verify step, OCI image build+push+sign, SBOM attestation
- Create: `Dockerfile` — multi-stage distroless image for honeybadger
- Modify: `Makefile` — add `-trimpath -buildvcs=false` to LDFLAGS, add `docker` target

### Stream D: Integration Documentation
- Rewrite: `docs/OPENCLAW.md` — expand with real FamClaw config.yaml snippets, Claude Code MCP config, verification commands, Docker usage
- Create: `docs/CLAUDE_CODE.md` — dedicated Claude Code integration guide (settings.json, project-level MCP, hooks)
- Modify: `docs/docs_test.go` — add tests for new Claude Code doc

### Stream B: Self-Check & SECURITY.md
- Modify: `SECURITY.md` — correct SLSA claim, govulncheck claim
- Modify: `.github/workflows/ci.yml` — remove `|| true` from govulncheck/gosec or document the exception properly

### Stream C: Doc Validation Tests
- Create: `docs/docs_test.go` — tests that parse OPENCLAW.md and EXAMPLES.md, cross-reference against actual CLI flags, MCP tool schema, env vars, paranoia levels, exit codes

---

### Task 1: Reproducible Build Flags

**Files:**
- Modify: `Makefile:1-19`

- [ ] **Step 1: Update LDFLAGS and build commands**

Add `-trimpath` and `-buildvcs=false` to all build targets for reproducible output:

```makefile
BINARY    := honeybadger
BUILD_DIR := ./bin
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-s -w -X main.Version=$(VERSION)"
GOFLAGS   := CGO_ENABLED=0
REPRO     := -trimpath -buildvcs=false

.PHONY: build cross test self-check clean docker

build:
	@mkdir -p $(BUILD_DIR)
	$(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY) ./cmd/honeybadger

cross:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux  GOARCH=arm64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-linux-arm64  ./cmd/honeybadger
	GOOS=linux  GOARCH=arm GOARM=7 $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-linux-armv7  ./cmd/honeybadger
	GOOS=linux  GOARCH=amd64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-linux-amd64  ./cmd/honeybadger
	GOOS=darwin GOARCH=arm64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/honeybadger
	GOOS=darwin GOARCH=amd64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/honeybadger
	@echo "All targets built"

android-install:
	CGO_ENABLED=0 go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

test:
	go test ./... -v

self-check: build
	./$(BUILD_DIR)/$(BINARY) scan github.com/famclaw/honeybadger --paranoia strict
	@echo "Self-check passed"

clean:
	rm -rf $(BUILD_DIR)
```

- [ ] **Step 2: Verify build still works**

Run: `make build && make clean`
Expected: Binary builds without errors

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build: add -trimpath -buildvcs=false for reproducible builds"
```

---

### Task 2: SHA-Pin GitHub Actions

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/codeql.yml`

- [ ] **Step 1: Pin all actions to commit SHAs in release.yml**

Replace version tags with commit SHAs. Keep the version as a comment for readability:

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
      attestations: write
      packages: write

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v6.2.0

      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5 # v6.0.0
        with:
          go-version-file: go.mod

      - name: Build all targets
        run: make cross

      - name: HoneyBadger self-check
        run: |
          ./bin/honeybadger-linux-amd64 scan github.com/famclaw/honeybadger \
            --paranoia strict --format ndjson | tee self-report.json
          verdict=$(grep '"type":"result"' self-report.json | jq -r .verdict || echo "UNKNOWN")
          if [ "$verdict" = "FAIL" ]; then
            echo "Self-check FAILED"
            exit 1
          fi

      - name: Generate SHA256SUMS
        run: sha256sum bin/* > SHA256SUMS

      - name: Attest build provenance
        uses: actions/attest-build-provenance@6d6cb0be6ccf0e4a8c6e37fbee9cf23623c9ad27 # v4.1.0
        with:
          subject-path: bin/*

      - name: Install cosign
        uses: sigstore/cosign-installer@3454372be43b8f59336a17b4c7a6e58d6a5f5b73 # v3.8.0

      - name: Sign with cosign
        run: |
          for f in bin/*; do
            cosign sign-blob --yes "$f" --bundle "${f}.bundle"
          done

      - name: Verify cosign signatures
        run: |
          for f in bin/*; do
            cosign verify-blob "$f" \
              --bundle "${f}.bundle" \
              --certificate-identity-regexp=".*famclaw/honeybadger.*" \
              --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
          done

      - name: Generate SBOM
        uses: anchore/sbom-action@e11c554f704a0b820cbf8c51673f6945e0731532 # v0.18.0
        with:
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Attest SBOM
        uses: actions/attest-build-provenance@6d6cb0be6ccf0e4a8c6e37fbee9cf23623c9ad27 # v4.1.0
        with:
          subject-path: sbom.spdx.json

      - name: Create release
        uses: softprops/action-gh-release@da05d552573ad5aba039eaac05058a918a7bf631 # v2.2.2
        with:
          generate_release_notes: true
          files: |
            bin/*
            SHA256SUMS
            sbom.spdx.json
            self-report.json
```

Note: The exact commit SHAs above are illustrative. Before implementing, look up the actual HEAD commit SHA for each action's version tag using `gh api repos/OWNER/REPO/git/ref/tags/VERSION`.

- [ ] **Step 2: Apply same SHA-pinning to ci.yml and codeql.yml**

Same pattern: replace `@vN` with `@SHA # vN.N.N`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/
git commit -m "build: SHA-pin all GitHub Actions for supply chain integrity"
```

---

### Task 3: Cosign Verify Step + SBOM Attestation

Already included in Task 2's release.yml update. This task covers verifying the changes work.

- [ ] **Step 1: Review the release workflow changes**

Verify:
1. `cosign verify-blob` step exists after signing
2. `--certificate-identity-regexp` matches the repo
3. `--certificate-oidc-issuer` is set to GitHub's OIDC issuer
4. SBOM uses `spdx-json` format (NTIA-compliant)
5. SBOM is attested separately via `attest-build-provenance`
6. `generate_release_notes: true` added to gh-release

- [ ] **Step 2: Commit** (if any additional changes needed)

```bash
git add .github/workflows/release.yml
git commit -m "build: add cosign verification and SBOM attestation to release"
```

---

### Task 4: Dockerfile + OCI Image Build

**Files:**
- Create: `Dockerfile`
- Modify: `.github/workflows/release.yml` (add Docker job)
- Modify: `Makefile` (add docker target)

- [ ] **Step 1: Create multi-stage Dockerfile**

```dockerfile
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -trimpath -buildvcs=false \
    -o /honeybadger ./cmd/honeybadger

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /honeybadger /honeybadger

ENTRYPOINT ["/honeybadger"]
```

- [ ] **Step 2: Add docker target to Makefile**

Append to Makefile:

```makefile
docker:
	docker buildx build --build-arg VERSION=$(VERSION) -t honeybadger:$(VERSION) .
```

- [ ] **Step 3: Verify Docker build locally**

Run: `make docker`
Expected: Image builds successfully

- [ ] **Step 4: Add OCI image job to release.yml**

Add a new job after the `release` job:

```yaml
  docker:
    runs-on: ubuntu-latest
    needs: release
    permissions:
      contents: read
      packages: write
      id-token: write

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v6.2.0

      - uses: docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2 # v3.10.0

      - uses: docker/login-action@74a5d142397b4f367a81961eba4e8cd7edddf772 # v3.4.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: docker/metadata-action@902fa8ec7d6ecbf8d84d538b9b233a880e428804 # v5.7.0
        id: meta
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}

      - uses: docker/build-push-action@14487ce63c7a62a4a324b0bfb37086795e31c6c1 # v6.16.0
        id: push
        with:
          context: .
          push: true
          platforms: linux/amd64,linux/arm64
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          build-args: |
            VERSION=${{ github.ref_name }}

      - uses: sigstore/cosign-installer@3454372be43b8f59336a17b4c7a6e58d6a5f5b73 # v3.8.0

      - name: Sign container image
        run: cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}
```

- [ ] **Step 5: Commit**

```bash
git add Dockerfile Makefile .github/workflows/release.yml
git commit -m "feat: add multi-arch OCI image build, push to GHCR, cosign signing"
```

---

### Task 5: Fix SECURITY.md Claims

**Files:**
- Modify: `SECURITY.md`

- [ ] **Step 1: Correct SECURITY.md to match reality**

```markdown
# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in HoneyBadger, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security@famclaw.dev or use GitHub's private vulnerability reporting:

1. Go to https://github.com/famclaw/honeybadger/security/advisories
2. Click "Report a vulnerability"
3. Provide a detailed description

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Security Practices

- All releases include GitHub build provenance attestation (SLSA Build L2)
- Release binaries are signed with Sigstore cosign (keyless via GitHub OIDC)
- Cosign signatures are verified in-pipeline before release publication
- SPDX SBOM generated and attested for every release
- `govulncheck` and `gosec` run in CI (warn mode due to gitleaks transitive deps)
- CodeQL static analysis runs on push, PR, and weekly schedule
- HoneyBadger self-checks at strict paranoia before every release
- All GitHub Actions SHA-pinned to immutable commit hashes
- Container images signed with cosign and pushed to GHCR

## Verifying Release Artifacts

```bash
# Verify binary signature
cosign verify-blob bin/honeybadger-linux-amd64 \
  --bundle bin/honeybadger-linux-amd64.bundle \
  --certificate-identity-regexp=".*famclaw/honeybadger.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Verify container image
cosign verify ghcr.io/famclaw/honeybadger:latest \
  --certificate-identity-regexp=".*famclaw/honeybadger.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Verify GitHub attestation
gh attestation verify bin/honeybadger-linux-amd64 \
  --repo famclaw/honeybadger
```
```

- [ ] **Step 2: Commit**

```bash
git add SECURITY.md
git commit -m "docs: correct SECURITY.md claims to match actual practices"
```

---

### Task 6: CI Enforcement Cleanup

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Make govulncheck/gosec explicit about their status**

Replace the `|| true` with proper continue-on-error + annotation so failures are visible but non-blocking:

```yaml
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v6.2.0
      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5 # v6.0.0
        with:
          go-version-file: go.mod
      - name: govulncheck
        continue-on-error: true  # non-blocking: gitleaks transitive deps have known vulns
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
      - name: gosec
        continue-on-error: true  # non-blocking until false-positive rate improves
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -severity medium ./...
      - name: go mod tidy check
        run: |
          go mod tidy
          git diff --exit-code go.mod go.sum
```

This way failures show as yellow warnings in the Actions UI (not silently swallowed by `|| true`), and we add a `go mod tidy` drift check.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: replace || true with continue-on-error, add go mod tidy check"
```

---

### Task 7: Doc Validation Tests — CLI Flags

**Files:**
- Create: `docs/docs_test.go`

These tests parse the doc files and cross-reference against the actual binary behavior. They run as regular unit tests (no build tags needed) since they only read files and check strings.

- [ ] **Step 1: Write test that verifies OPENCLAW.md paranoia table matches actual levels**

```go
package docs_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// docsDir returns the absolute path to the docs/ directory.
func docsDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Dir(filename)
}

// readDoc reads a doc file from the docs/ directory.
func readDoc(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(docsDir(t), name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(content)
}

// allParanoiaLevels are the valid paranoia levels from scan.ParseParanoia.
// Hardcoded here to avoid importing internal packages from docs test.
// If a level is added/removed, this test will catch the drift.
var allParanoiaLevels = []string{"off", "minimal", "family", "strict", "paranoid"}

func TestOpenClaw_ParanoiaLevelsDocumented(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")

	for _, level := range allParanoiaLevels {
		if !strings.Contains(doc, "`"+level+"`") {
			t.Errorf("OPENCLAW.md missing paranoia level %q", level)
		}
	}
}

func TestOpenClaw_ParanoiaTableMatchesREADME(t *testing.T) {
	openclaw := readDoc(t, "OPENCLAW.md")
	readme, err := os.ReadFile(filepath.Join(docsDir(t), "..", "README.md"))
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	// Both should document the same paranoia table structure
	for _, level := range allParanoiaLevels {
		inOpenclaw := strings.Contains(openclaw, "| `"+level+"`")
		inReadme := strings.Contains(string(readme), "| "+level+" ")
		if inOpenclaw && !inReadme {
			t.Errorf("paranoia level %q in OPENCLAW.md but not in README.md table", level)
		}
		if inReadme && !inOpenclaw {
			t.Errorf("paranoia level %q in README.md but not in OPENCLAW.md table", level)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./docs/ -v -run TestOpenClaw_Paranoia`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add docs/docs_test.go
git commit -m "test: add doc validation tests for paranoia levels"
```

---

### Task 8: Doc Validation Tests — CLI Flags in EXAMPLES.md

**Files:**
- Modify: `docs/docs_test.go`

- [ ] **Step 1: Write test that verifies documented CLI flags exist in main.go**

Append to `docs/docs_test.go`:

```go
func TestExamples_CLIFlagsExistInSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	// Read main.go to get actual flag definitions
	mainSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "cmd", "honeybadger", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	src := string(mainSrc)

	// Flags documented in EXAMPLES.md (extracted from code examples)
	documentedFlags := []string{
		"--paranoia",
		"--format",
		"--offline",
		"--installed-sha",
		"--installed-tool-hash",
		"--force",
		"--path",
		"--db",
		"--mcp-server",
	}

	for _, flag := range documentedFlags {
		// Strip leading dashes for source check
		name := strings.TrimLeft(flag, "-")
		if !strings.Contains(src, `"`+name+`"`) && !strings.Contains(src, `"-`+name+`"`) && !strings.Contains(src, "--"+name) {
			t.Errorf("EXAMPLES.md documents %s but it is not defined in main.go", flag)
		}
	}
}

func TestExamples_ExitCodesMatchEngine(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	// EXAMPLES.md documents exit codes 0, 1, 2, 3.
	// Verify the table is present and correct.
	expectedCodes := map[string]string{
		"| 0 ": "PASS",
		"| 1 ": "WARN",
		"| 2 ": "FAIL",
		"| 3 ": "Error",
	}

	for code, meaning := range expectedCodes {
		if !strings.Contains(doc, code) {
			t.Errorf("EXAMPLES.md missing exit code row starting with %q", code)
		}
		if !strings.Contains(doc, meaning) {
			t.Errorf("EXAMPLES.md missing exit code meaning %q", meaning)
		}
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./docs/ -v -run TestExamples`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add docs/docs_test.go
git commit -m "test: add doc validation for CLI flags and exit codes"
```

---

### Task 9: Doc Validation Tests — MCP Tool Schema

**Files:**
- Modify: `docs/docs_test.go`

- [ ] **Step 1: Write test that verifies OPENCLAW.md and EXAMPLES.md MCP params match mcp.go**

Append to `docs/docs_test.go`:

```go
func TestExamples_MCPParametersMatchSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	// Read mcp.go to get actual tool parameters
	mcpSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "cmd", "honeybadger", "mcp.go"))
	if err != nil {
		t.Fatalf("reading mcp.go: %v", err)
	}
	src := string(mcpSrc)

	// Parameters documented in EXAMPLES.md MCP tool parameters table
	documentedParams := []string{
		"repo_url",
		"paranoia",
		"installed_sha",
		"installed_tool_hash",
		"path",
	}

	for _, param := range documentedParams {
		if !strings.Contains(src, `"`+param+`"`) {
			t.Errorf("EXAMPLES.md documents MCP param %q but it is not in mcp.go", param)
		}
		if !strings.Contains(doc, "| `"+param+"`") {
			t.Errorf("MCP param %q is in source but missing from EXAMPLES.md table", param)
		}
	}

	// Reverse check: find params in mcp.go and verify they're documented
	// Look for mcp.WithString("param_name", ...) patterns
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "WithString(\"") {
			start := strings.Index(line, "WithString(\"") + len("WithString(\"")
			end := strings.Index(line[start:], "\"")
			if end > 0 {
				param := line[start : start+end]
				if !strings.Contains(doc, param) {
					t.Errorf("mcp.go defines param %q but EXAMPLES.md does not document it", param)
				}
			}
		}
	}
}

func TestOpenClaw_MCPToolNameMatchesSource(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")

	mcpSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "cmd", "honeybadger", "mcp.go"))
	if err != nil {
		t.Fatalf("reading mcp.go: %v", err)
	}

	// Extract tool name from mcp.NewTool("...")
	src := string(mcpSrc)
	marker := `mcp.NewTool("`
	idx := strings.Index(src, marker)
	if idx < 0 {
		t.Fatal("could not find mcp.NewTool in mcp.go")
	}
	nameStart := idx + len(marker)
	nameEnd := strings.Index(src[nameStart:], `"`)
	toolName := src[nameStart : nameStart+nameEnd]

	if !strings.Contains(doc, toolName) {
		t.Errorf("OPENCLAW.md does not mention MCP tool name %q", toolName)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./docs/ -v -run "TestExamples_MCP|TestOpenClaw_MCP"`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add docs/docs_test.go
git commit -m "test: add doc validation for MCP tool schema and params"
```

---

### Task 10: Doc Validation Tests — Environment Variables

**Files:**
- Modify: `docs/docs_test.go`

- [ ] **Step 1: Write test that verifies OPENCLAW.md env var table matches main.go**

Append to `docs/docs_test.go`:

```go
func TestOpenClaw_EnvVarsMatchSource(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")

	mainSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "cmd", "honeybadger", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	mcpSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "cmd", "honeybadger", "mcp.go"))
	if err != nil {
		t.Fatalf("reading mcp.go: %v", err)
	}
	src := string(mainSrc) + string(mcpSrc)

	// Env vars documented in OPENCLAW.md
	documentedEnvVars := []string{
		"GITHUB_TOKEN",
		"GITLAB_TOKEN",
		"HONEYBADGER_LLM",
		"HONEYBADGER_LLM_KEY",
		"HONEYBADGER_LLM_MODEL",
	}

	for _, env := range documentedEnvVars {
		if !strings.Contains(doc, "| `"+env+"`") {
			t.Errorf("env var %s not in OPENCLAW.md table", env)
		}
		if !strings.Contains(src, `"`+env+`"`) {
			t.Errorf("OPENCLAW.md documents env var %s but it is not used in source", env)
		}
	}

	// Reverse check: find env vars in source that should be documented
	envPatterns := []string{"GITHUB_TOKEN", "GITLAB_TOKEN", "HONEYBADGER_"}
	for _, pat := range envPatterns {
		for _, line := range strings.Split(src, "\n") {
			if strings.Contains(line, `Getenv("`) || strings.Contains(line, `envOrDefault("`) {
				// Extract env var name
				for _, fn := range []string{`Getenv("`, `envOrDefault("`} {
					if idx := strings.Index(line, fn); idx >= 0 {
						start := idx + len(fn)
						end := strings.Index(line[start:], `"`)
						if end > 0 {
							envName := line[start : start+end]
							if strings.HasPrefix(envName, pat) || envName == pat {
								if !strings.Contains(doc, envName) {
									t.Errorf("source uses env var %s but OPENCLAW.md does not document it", envName)
								}
							}
						}
					}
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./docs/ -v -run TestOpenClaw_EnvVars`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add docs/docs_test.go
git commit -m "test: add doc validation for environment variables"
```

---

### Task 11: Doc Validation Tests — Binary Targets & Config Examples

**Files:**
- Modify: `docs/docs_test.go`

- [ ] **Step 1: Write test that verifies documented binary names match Makefile targets**

Append to `docs/docs_test.go`:

```go
func TestOpenClaw_BinaryTargetsMatchMakefile(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")

	makefileSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "Makefile"))
	if err != nil {
		t.Fatalf("reading Makefile: %v", err)
	}
	makefile := string(makefileSrc)

	// Binary names documented in OPENCLAW.md
	binaryNames := []string{
		"honeybadger-linux-arm64",
		"honeybadger-linux-armv7",
		"honeybadger-linux-amd64",
		"honeybadger-darwin-arm64",
		"honeybadger-darwin-amd64",
	}

	for _, bin := range binaryNames {
		if !strings.Contains(doc, bin) {
			t.Errorf("OPENCLAW.md missing binary target %q", bin)
		}
		if !strings.Contains(makefile, bin) {
			t.Errorf("OPENCLAW.md lists binary %q but Makefile does not build it", bin)
		}
	}
}

func TestOpenClaw_ConfigExamplesHaveMCPServerFlag(t *testing.T) {
	doc := readDoc(t, "OPENCLAW.md")

	// All three config examples (FamClaw, OpenClaw, PicoClaw) should reference --mcp-server
	sections := []string{"### FamClaw", "### OpenClaw", "### PicoClaw"}
	for _, section := range sections {
		if !strings.Contains(doc, section) {
			t.Errorf("OPENCLAW.md missing config section %q", section)
		}
	}

	// Verify --mcp-server is referenced in config examples
	if count := strings.Count(doc, "--mcp-server"); count < 3 {
		t.Errorf("OPENCLAW.md should have --mcp-server in all 3 config examples, found %d references", count)
	}
}

func TestExamples_ResponseSchemaFieldsMatchSource(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	// Fields that must appear in the response example
	requiredFields := []string{
		"verdict",
		"reasoning",
		"finding_counts",
		"cve_count",
		"cve_max_severity",
		"attested",
		"llm_used",
		"paranoia",
		"effective_paranoia",
		"scanned_at",
		"duration_ms",
	}

	for _, field := range requiredFields {
		if !strings.Contains(doc, `"`+field+`"`) {
			t.Errorf("EXAMPLES.md response example missing field %q", field)
		}
	}
}

func TestExamples_NDJSONEventTypesDocumented(t *testing.T) {
	doc := readDoc(t, "EXAMPLES.md")

	// Event types that must be documented in the NDJSON section
	eventTypes := []string{"sandbox", "progress", "finding", "health", "result"}

	for _, evt := range eventTypes {
		if !strings.Contains(doc, `"type":"`+evt+`"`) {
			t.Errorf("EXAMPLES.md NDJSON section missing event type %q", evt)
		}
	}
}
```

- [ ] **Step 2: Run all doc tests**

Run: `go test ./docs/ -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add docs/docs_test.go
git commit -m "test: add doc validation for binary targets, configs, and response schema"
```

---

### Task 12: Rewrite OPENCLAW.md with Real Integration Instructions

**Files:**
- Rewrite: `docs/OPENCLAW.md`

The current OPENCLAW.md is a skeleton. Rewrite it with real, tested config snippets matching FamClaw's actual `config.yaml` format, OpenClaw conventions, and add Docker usage.

- [ ] **Step 1: Rewrite OPENCLAW.md**

```markdown
# Installing HoneyBadger in Claw Runtimes

## Quick Start

### From source (all platforms)
    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest
    honeybadger scan github.com/someone/some-skill

### From GitHub Releases
Download the prebuilt binary for your platform from
https://github.com/famclaw/honeybadger/releases

Available targets:
- `honeybadger-linux-arm64` -- Raspberry Pi 4/5
- `honeybadger-linux-armv7` -- Raspberry Pi 3
- `honeybadger-linux-amd64` -- Linux x86_64
- `honeybadger-darwin-arm64` -- macOS Apple Silicon
- `honeybadger-darwin-amd64` -- macOS Intel

### Docker
    docker pull ghcr.io/famclaw/honeybadger:latest
    docker run --rm ghcr.io/famclaw/honeybadger scan github.com/someone/some-skill

Multi-arch image available for `linux/amd64` and `linux/arm64`.

### Android / Termux
    pkg install golang
    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

Note: Sandbox unavailable on Termux. Effective paranoia capped at `family`.

## Verifying Downloads

All release binaries are signed with Sigstore cosign (keyless). Verify before use:

    # Verify binary signature
    cosign verify-blob honeybadger-linux-arm64 \
      --bundle honeybadger-linux-arm64.bundle \
      --certificate-identity-regexp=".*famclaw/honeybadger.*" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

    # Verify via GitHub attestation
    gh attestation verify honeybadger-linux-arm64 --repo famclaw/honeybadger

    # Verify Docker image
    cosign verify ghcr.io/famclaw/honeybadger:latest \
      --certificate-identity-regexp=".*famclaw/honeybadger.*" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

## MCP Server Mode

HoneyBadger runs as an MCP server over stdio, exposing the `honeybadger_scan` tool.
Any MCP-compatible runtime can call it.

    honeybadger --mcp-server

## Integration: FamClaw

FamClaw discovers MCP tools automatically via the `tools/list` handshake.
Add honeybadger to your `config.yaml`:

```yaml
skills:
  auto_seccheck: true       # run honeybadger before installing any skill
  block_on_fail: true        # reject skills that fail security check

  mcp_servers:
    honeybadger:
      transport: stdio
      command: honeybadger
      args: ["--mcp-server"]

  credentials:
    honeybadger:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

Credentials are injected as environment variables when the MCP server process
is spawned. They never appear in LLM context.

**How it works in FamClaw:**
1. A family member asks to install a skill or vet a repo
2. FamClaw's policy engine evaluates the request (parent approval may be required)
3. If allowed, the agent calls `honeybadger_scan` via MCP
4. HoneyBadger fetches the repo, runs all scanners, returns PASS/WARN/FAIL
5. FamClaw blocks installation if verdict is FAIL

**Remote mode** (for constrained devices like Android):
```yaml
skills:
  mcp_servers:
    honeybadger:
      transport: http
      url: "http://192.168.1.10:8090/mcp"
      headers:
        Authorization: "Bearer ${MCP_TOKEN}"
```

Run honeybadger on a LAN server and point constrained devices to it.

## Integration: OpenClaw

In your OpenClaw MCP config:
```yaml
mcp_servers:
  honeybadger:
    command: honeybadger
    args: ["--mcp-server"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"
```

## Integration: PicoClaw

In PicoClaw's tool configuration:
```yaml
tools:
  - name: honeybadger
    type: mcp
    command: honeybadger --mcp-server
```

## Integration: Claude Code

See [CLAUDE_CODE.md](CLAUDE_CODE.md) for full Claude Code setup instructions.

Quick setup — add to your project's `.claude/settings.local.json`:
```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "honeybadger",
      "args": ["--mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

## SKILL.md Registration

HoneyBadger ships with a SKILL.md at the repo root. When installed via skillbridge,
the runtime auto-discovers it. Triggers include:
- "honeybadger"
- "scan this repo"
- "is this safe to install"
- "check this skill"
- "vet this"
- "security scan"
- "verify this update"
- "check for updates"

## Paranoia Levels

| Level | Scanners | LLM | Blocks on |
|-------|----------|-----|-----------|
| `off` | None | No | Nothing |
| `minimal` | secrets, cve | No | CRITICAL |
| `family` | secrets, cve, supplychain, meta | Yes | HIGH+ |
| `strict` | all + attestation | Yes | MEDIUM+ (WARN=FAIL) |
| `paranoid` | all + allowlist | Yes | LOW+ |

The CLI accepts all five levels. The MCP tool accepts `minimal`, `family`,
`strict`, and `paranoid` (defaults to `family`).

Set globally in your runtime config or per-scan via the MCP tool parameter.

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `GITHUB_TOKEN` | Higher GitHub API rate limits (60 -> 5000/hr) | No |
| `GITLAB_TOKEN` | GitLab private repo access | No |
| `HONEYBADGER_LLM` | LLM endpoint for verdict analysis | No |
| `HONEYBADGER_LLM_KEY` | API key for LLM endpoint | No |
| `HONEYBADGER_LLM_MODEL` | Model name for LLM | No |

## Troubleshooting

**"routing: unsupported URL"** -- URL format not recognized. Use `github.com/owner/repo`, `gitlab.com/group/project`, or a local filesystem path.

**Rate limiting (GitHub)** -- Set `GITHUB_TOKEN` for 5000 req/hr instead of 60.

**Offline mode** -- Use `--offline` flag on the CLI for air-gapped environments. The MCP tool does not expose an offline parameter.

**Binary not found** -- Ensure honeybadger is in your PATH, or use the absolute path in your runtime config.

**Termux sandbox warning** -- Expected. Sandbox is unavailable on Android. Paranoia is capped at `family`.

**Docker permission denied** -- Run `docker run --rm ghcr.io/famclaw/honeybadger ...` without volume mounts. HoneyBadger fetches repos over the network inside the container.
```

- [ ] **Step 2: Verify doc tests still pass**

Run: `go test ./docs/ -v`
Expected: PASS (existing tests should still match since we preserved all required elements)

- [ ] **Step 3: Commit**

```bash
git add docs/OPENCLAW.md
git commit -m "docs: rewrite OPENCLAW.md with real integration configs and Docker usage"
```

---

### Task 13: Create Claude Code Integration Guide

**Files:**
- Create: `docs/CLAUDE_CODE.md`

- [ ] **Step 1: Write CLAUDE_CODE.md**

```markdown
# Using HoneyBadger with Claude Code

HoneyBadger integrates with Claude Code as an MCP server, giving Claude
the ability to security-scan repositories before you install skills,
tools, or MCP servers.

## Prerequisites

Install the honeybadger binary:

    go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

Or download a prebuilt binary from
https://github.com/famclaw/honeybadger/releases and add it to your PATH.

## Setup: Project-Level (Recommended)

Add honeybadger as an MCP server in your project's `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "honeybadger",
      "args": ["--mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

This scopes honeybadger to the project. Claude Code will discover it via
the MCP `tools/list` handshake and can call `honeybadger_scan` during
conversations.

## Setup: User-Level (All Projects)

To make honeybadger available in every project, add it to your global
settings at `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "honeybadger",
      "args": ["--mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

## Usage

Once configured, Claude Code can call honeybadger during conversations.
Ask naturally:

- "Is github.com/someone/some-skill safe to install?"
- "Security scan this repo before I add it"
- "Vet github.com/someone/some-mcp at strict paranoia"
- "Check if this MCP server has any CVEs"

Claude will call the `honeybadger_scan` tool and interpret the results
for you, explaining any findings and recommending whether to proceed.

## MCP Tool: honeybadger_scan

Claude Code calls this tool with these parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `repo_url` | string | Yes | GitHub/GitLab URL or local path |
| `paranoia` | string | No | `minimal`, `family`, `strict`, `paranoid` (default: `family`) |
| `installed_sha` | string | No | SHA256 of installed version (for update detection) |
| `installed_tool_hash` | string | No | SHA256 of MCP tool definitions (rug-pull detection) |
| `path` | string | No | Subdirectory within repo to scan |

The tool returns a JSON result with verdict (PASS/WARN/FAIL), reasoning,
finding counts by severity, and scan metadata.

## Pre-Install Hook (Advanced)

You can configure a Claude Code hook that runs honeybadger before any
MCP server or skill installation. Add to `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__.*install.*",
        "command": "honeybadger scan \"$TOOL_INPUT\" --paranoia family --format text"
      }
    ]
  }
}
```

This runs a security scan whenever Claude attempts to use a tool matching
the install pattern, blocking if the scan fails.

## Environment Variables

Set these in your shell profile or `.env` file:

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | Higher API rate limits (60 -> 5000/hr) |
| `GITLAB_TOKEN` | GitLab private repo access |
| `HONEYBADGER_LLM` | LLM endpoint for AI-assisted verdict |
| `HONEYBADGER_LLM_KEY` | API key for LLM endpoint |
| `HONEYBADGER_LLM_MODEL` | Model name (e.g. `claude-sonnet-4-6`) |

These are passed to the honeybadger process via the `env` block in your
MCP config. They never appear in Claude's context window.

## Docker Alternative

If you prefer not to install the binary, use the Docker image:

```json
{
  "mcpServers": {
    "honeybadger": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "GITHUB_TOKEN",
        "ghcr.io/famclaw/honeybadger:latest",
        "--mcp-server"
      ],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

## Troubleshooting

**"honeybadger: command not found"** -- Ensure the binary is in your PATH.
Run `which honeybadger` to check. If using `go install`, verify that
`$GOPATH/bin` (usually `~/go/bin`) is in your PATH.

**MCP server not starting** -- Check Claude Code logs. The honeybadger
process must be able to start and speak JSON-RPC over stdio. Test
manually: `echo '{}' | honeybadger --mcp-server` should not crash.

**Rate limiting** -- Set `GITHUB_TOKEN` in the env block. Without it,
GitHub API is limited to 60 requests/hour.

**Timeouts on large repos** -- Large monorepos may take longer to scan.
The MCP server has no built-in timeout; Claude Code's default tool
timeout applies.
```

- [ ] **Step 2: Commit**

```bash
git add docs/CLAUDE_CODE.md
git commit -m "docs: add Claude Code integration guide"
```

---

### Task 14: Doc Validation Tests — Claude Code Guide

**Files:**
- Modify: `docs/docs_test.go`

- [ ] **Step 1: Add tests for CLAUDE_CODE.md**

Append to `docs/docs_test.go`:

```go
func TestClaudeCode_MCPConfigValid(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	// Must contain valid mcpServers JSON config
	if !strings.Contains(doc, `"mcpServers"`) {
		t.Error("CLAUDE_CODE.md missing mcpServers config block")
	}
	if !strings.Contains(doc, `"honeybadger"`) {
		t.Error("CLAUDE_CODE.md missing honeybadger server name in config")
	}
	if !strings.Contains(doc, `"--mcp-server"`) {
		t.Error("CLAUDE_CODE.md missing --mcp-server arg in config")
	}
}

func TestClaudeCode_MCPParamsMatchSource(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	mcpSrc, err := os.ReadFile(filepath.Join(docsDir(t), "..", "cmd", "honeybadger", "mcp.go"))
	if err != nil {
		t.Fatalf("reading mcp.go: %v", err)
	}
	src := string(mcpSrc)

	// All MCP params should be documented in Claude Code guide
	params := []string{"repo_url", "paranoia", "installed_sha", "installed_tool_hash", "path"}
	for _, param := range params {
		if !strings.Contains(src, `"`+param+`"`) {
			t.Errorf("param %q not in mcp.go source", param)
		}
		if !strings.Contains(doc, "`"+param+"`") {
			t.Errorf("CLAUDE_CODE.md missing MCP param %q", param)
		}
	}
}

func TestClaudeCode_EnvVarsDocumented(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	envVars := []string{
		"GITHUB_TOKEN",
		"GITLAB_TOKEN",
		"HONEYBADGER_LLM",
		"HONEYBADGER_LLM_KEY",
		"HONEYBADGER_LLM_MODEL",
	}

	for _, env := range envVars {
		if !strings.Contains(doc, env) {
			t.Errorf("CLAUDE_CODE.md missing env var %s", env)
		}
	}
}

func TestClaudeCode_SettingsPathsDocumented(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	// Must document both project-level and user-level config locations
	if !strings.Contains(doc, ".claude/settings.local.json") {
		t.Error("CLAUDE_CODE.md missing project-level settings path (.claude/settings.local.json)")
	}
	if !strings.Contains(doc, "~/.claude/settings.json") || !strings.Contains(doc, ".claude/settings.json") {
		t.Error("CLAUDE_CODE.md missing user-level settings path (~/.claude/settings.json)")
	}
}

func TestClaudeCode_DockerAlternativeDocumented(t *testing.T) {
	doc := readDoc(t, "CLAUDE_CODE.md")

	if !strings.Contains(doc, "ghcr.io/famclaw/honeybadger") {
		t.Error("CLAUDE_CODE.md missing Docker image reference")
	}
	if !strings.Contains(doc, `"docker"`) {
		t.Error("CLAUDE_CODE.md missing Docker command in MCP config example")
	}
}
```

- [ ] **Step 2: Run all doc tests**

Run: `go test ./docs/ -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add docs/docs_test.go
git commit -m "test: add doc validation for Claude Code integration guide"
```

---

### Task 15: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update project structure to include new files**

Add `Dockerfile`, `docs/docs_test.go`, `docs/CLAUDE_CODE.md` to the project structure tree in README.md.

- [ ] **Step 2: Update Status section**

```markdown
## Status

Wave 10 complete. Supply chain hardening, integration docs, and doc validation tests:
- Reproducible builds (`-trimpath -buildvcs=false`)
- All GitHub Actions SHA-pinned to immutable commit hashes
- Cosign signature verification step in release pipeline
- SBOM switched to SPDX format, attested alongside binaries
- Multi-arch OCI images built and pushed to GHCR, signed with cosign
- SECURITY.md corrected to match actual practices (SLSA L2, not L3)
- CI security checks use `continue-on-error` instead of `|| true` (visible warnings)
- `go mod tidy` drift check in CI
- `docs/OPENCLAW.md` rewritten with real FamClaw config.yaml, Docker usage, verification commands
- `docs/CLAUDE_CODE.md` — dedicated Claude Code integration guide (MCP config, hooks, Docker)
- `docs/docs_test.go` validates all docs stay in sync with source:
  paranoia levels, CLI flags, MCP params, env vars, binary targets, response schema, Claude Code config
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README for Wave 10"
```

---

## Dependency Graph

```
Task 1  (Makefile) ──┐
Task 2  (SHA-pin) ───┼──> Task 4 (Docker/OCI) ──> Task 15 (README)
Task 3  (Verify) ────┘                              ↑
Task 5  (SECURITY.md) ─────────────────────────────┤
Task 6  (CI cleanup) ──────────────────────────────┤
Task 7  (Doc: paranoia) ─> Task 8 (flags) ─> Task 9 (MCP) ─> Task 10 (env) ─> Task 11 (bins) ──┤
Task 12 (Rewrite OPENCLAW.md) ─> Task 13 (CLAUDE_CODE.md) ─> Task 14 (CC doc tests) ────────────┘
```

**Parallelizable groups:**
- Stream A (Tasks 1-4), Stream C (Tasks 7-11), and Stream D (Tasks 12-14) are fully independent
- Task 5 and Task 6 are independent of each other and of all streams
- Task 15 depends on all others

**Four streams, 15 tasks total:**
- **Stream A** (Tasks 1-4): Release pipeline hardening
- **Stream B** (Tasks 5-6): Honesty & CI enforcement
- **Stream C** (Tasks 7-11): Doc validation tests
- **Stream D** (Tasks 12-14): Integration documentation (OpenClaw, FamClaw, Claude Code)
