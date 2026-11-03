# Evidence Receipts & Secure Supply Chain

## Overview

The Evidence Receipts and Secure Scanner Supply Chain system provides structured, verifiable receipts for HoneyBadger scans. Receipts record exactly which checks were executed, what was verified, what was only calculated, and what is a documented placeholder — so that "verification" is never conflated with "presence".

## What is implemented (real behavior)

### Evidence receipt structure
- `EvidenceReceipt` records the scan subject, scanner/rule/policy versions, the checks that actually ran, findings, documented exceptions, pinned build actions, and published assets.
- `GenerateDigest()` computes a stable SHA256 digest of the receipt's JSON representation. **This is a content digest, not a signature.**

### Artifact digest verification, separated from presence
The receipt's `verification` field distinguishes outcomes:

| Status | Meaning |
|---|---|
| `not_performed` | The target was not a local readable file; no digest check ran |
| `calculated` | The SHA256 digest was computed, but **no trusted baseline was registered**, so no comparison happened. An INFO finding (`sup-target-no-baseline`) documents the gap. |
| `verified` | The computed digest was **compared against a trusted baseline and matched** |
| `digest_mismatch` | A baseline was registered but the computed digest differs (HIGH finding `sup-target-digest-mismatch`) |
| `unavailable` | The file could not be read, so no digest could be computed (finding only when a baseline is registered) |

Baselines are registered with `AddArtifactBaseline(name, expectedDigest)`; names match by full asset string or basename. A digest that was merely computed can never make the receipt say `verified`.

### Published asset verification
`VerifyPublishedAssets()` returns one `AssetVerification` per asset with an explicit status — the old substring heuristic ("verified" if the name contains "valid") is gone:

| Status | Meaning |
|---|---|
| `verified` | Computed SHA256 of the local file matches the trusted baseline |
| `unverified` | No trusted baseline registered (assets without a baseline are never marked verified), or a remote asset with no baseline |
| `digest_mismatch` | Baseline present, computed digest differs (HIGH finding) |
| `unavailable` | Baseline present but the asset is not locally readable (LOW finding) |

Remote URL assets are **not fetched offline**. With a baseline they report `unavailable`; without one, `unverified`. Acceptance gate for remote verification: a bounded, reviewed fetch-and-compare path (or signature check) — see below.

### Build action pin verification
`SecureScan` checks every pinned build action for pin strength:
- Commit-SHA pins (`owner/name@<40-hex>`) and content-digest pins (`image@sha256:<64-hex>`) pass.
- Floating references (`@latest`, `:stable`, `:current`, `:nightly`) produce a MEDIUM finding (`sup-build-action-floating`).
- Soft references that can move (e.g. `@main`, `@v4`) produce a LOW finding (`sup-build-action-soft-ref`).
- References with no version at all produce a LOW finding (`sup-build-action-unpinned`).

### Security exception gating
Security exceptions registered on the supply chain are documented on the receipt in stable (ID-sorted) order under the `security-exceptions` check.

### Secure scan
`SecureScan(target, scannerVersion, ruleVersion, policyVersion)` runs the real checks above and returns a receipt whose `checks` list contains **only the checks that actually executed** — no hardcoded check names with no corresponding work.

## Documented placeholders (not implemented — do not treat as security controls)

### Optional signed export
**Not implemented.** The `SignedExport` flag and `SetSignedExport` have been removed. `GenerateDigest()` produces a content digest only: anyone can compute it, and it cannot be verified against a trusted key.

Acceptance gate: a signing/verification path with a trusted key — e.g. detached ed25519/GPG/sigstore signature over the receipt JSON — plus a receipt field that is set to a verified signature state only after real signature verification. New crypto dependencies require captain approval before they are added.

### Remote asset fetch-and-compare
**Not implemented.** URL assets are reported `unverified`/`unavailable` instead of being fetched. Acceptance gate: a bounded HTTP fetch (size/timeout limits, reviewed) followed by baseline digest comparison, or signature verification against a trusted key.

## HB-10 acceptance status

| Requirement | Status | Notes |
|---|---|---|
| Evidence receipt names subject, versions, checks, findings, exceptions | Implemented | `EvidenceReceipt` + `SecureScan` |
| Separate artifact digest verification from presence | Implemented | `calculated` vs `verified` vs `digest_mismatch`; baseline required for `verified` |
| Verify published assets | Implemented for local assets with baselines | Explicit `unverified`/`unavailable` when no baseline or not locally readable; remote fetch documented as placeholder |
| Pin build actions | Implemented | Pin strength verified in `SecureScan` (floating/soft/unpinned → findings) |
| Gate/document security exceptions | Implemented | Exceptions recorded on the receipt, ID-sorted |
| Optional signed export | **Documented placeholder** | Removed as a false flag; content digest only; acceptance gate above |

## Usage

```go
// real examples only
ssc := scanner.NewSecureScannerSupplyChain(basePath)
ssc.AddArtifactBaseline("release.tar.gz", knownGoodSHA256)
ssc.AddPublishedAsset(filepath.Join(basePath, "release.tar.gz"))
ssc.PinBuildAction("actions/checkout@8f4b73f5cef00d4e66f97b0c1e8e9f8b1a2c3d4e")

receipt, err := ssc.SecureScan(target, scannerVersion, ruleVersion, policyVersion)
```

The receipt's `verification` field, per-asset statuses, and `checks` list record what actually happened; findings carry machine-readable rule IDs (`sup-*`) for downstream gating.
