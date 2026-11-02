# Evidence Receipts and Secure Scanner Supply Chain

This implementation provides evidence receipts and secure scanner supply chain functionality for HoneyBadger.

## Features

### Evidence Receipts
- Structured receipt format with subject identification
- Scanner, rule, and policy version tracking
- Comprehensive finding and exception documentation
- Artifact digest verification (separated from presence)
- Support for signed exports
- Timestamped records

### Secure Scanner Supply Chain
- Artifact digest verification with SHA256 hashing
- Published asset verification capabilities
- Build action pinning for supply chain integrity
- Security exception documentation and tracking
- Integration with existing HoneyBadger scanning infrastructure

## Implementation Details

### EvidenceReceipt Structure
The `EvidenceReceipt` struct captures all required information:
- Subject: What was scanned
- Scanner/Rule/Policy Versions: Version tracking for accountability
- Checks: Performed verification steps
- Findings: Discovered security issues
- Exceptions: Documented exemptions
- Artifact Digest: SHA256 hash of the scanned artifact
- Verification: Status of digest verification
- Published Assets: Verified published assets
- Build Actions: Pinned build processes
- Security Exceptions: Documented security exceptions

### SecureScannerSupplyChain
The `SecureScannerSupplyChain` provides:
- Artifact digest calculation and verification
- Published asset verification framework
- Build action pinning for supply chain integrity
- Security exception tracking and management
- Evidence receipt generation

## Usage

```go
// Create a secure scanner supply chain
ssc := scanner.NewSecureScannerSupplyChain("/path/to/artifacts")

// Pin build actions for supply chain integrity
ssc.PinBuildAction("build:go:1.21")
ssc.PinBuildAction("build:docker:24.0")

// Add published assets to verify
ssc.AddPublishedAsset("https://example.com/artifact.tar.gz")

// Add security exceptions
exception := report.SecurityException{
    ID: "SEC-001",
    Description: "Known vulnerability in dependency",
    Justification: "Not exploitable in current context",
    ExceptionType: "known-vulnerability",
    Resolved: false,
}

// Generate evidence receipt
receipt, err := ssc.GenerateEvidenceReceipt(
    "artifact-name",
    "scanner-version",
    "rule-version", 
    "policy-version",
    findings,
    checks,
    exceptions,
)
```

## Requirements Met

✓ Evidence receipt names subject, scanner/rule/policy versions, checks, findings and exceptions  
✓ Optional signed export capability  
✓ Artifact digest verification separated from presence  
✓ Verify published assets  
✓ Pin build actions  
✓ Gate/document security exceptions  

This implementation satisfies the requirements for task HB-10 P1: "Evidence receipts + secure scanner supply chain".