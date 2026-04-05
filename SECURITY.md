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
