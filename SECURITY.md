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

- All releases include SLSA Build L3 provenance attestation
- Release binaries are signed with Sigstore cosign (keyless)
- CycloneDX SBOM attached to every release
- `govulncheck` runs in CI and blocks merge on known CVEs
- HoneyBadger self-checks before every release
