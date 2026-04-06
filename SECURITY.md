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
- HoneyBadger self-checks before every release (strict paranoia after v0.1.0;
  v0.1.0 used minimal due to attestation bootstrap — no prior release to verify against)
- GitHub Actions pinned to version tags; Dependabot keeps them updated
- Container images signed with cosign and pushed to GHCR

## Verifying Release Artifacts

HoneyBadger uses a two-layer verification model:
1. Cosign signs the **SHA256SUMS** file (not individual binaries)
2. Individual binaries are verified against the signed checksum file

### Step 1 — Verify the checksum file signature

```bash
curl -fsSL https://github.com/famclaw/honeybadger/releases/latest/download/SHA256SUMS \
  -o SHA256SUMS
curl -fsSL https://github.com/famclaw/honeybadger/releases/latest/download/SHA256SUMS.bundle \
  -o SHA256SUMS.bundle

cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp ".*famclaw/honeybadger.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Step 2 — Verify your binary against the checksum file

```bash
curl -fsSL https://github.com/famclaw/honeybadger/releases/latest/download/honeybadger-linux-amd64 \
  -o honeybadger-linux-amd64

sha256sum --check --ignore-missing SHA256SUMS
```

### GitHub Attestation (alternative)

```bash
gh attestation verify honeybadger-linux-amd64 --repo famclaw/honeybadger
```

### Docker image

```bash
cosign verify ghcr.io/famclaw/honeybadger:latest \
  --certificate-identity-regexp ".*famclaw/honeybadger.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
