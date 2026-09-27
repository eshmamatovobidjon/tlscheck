# TLSCheck

A practical Go CLI for inspecting and validating TLS connections and X.509 certificates.

The project is intentionally being built incrementally to learn Go through a real-world project rather than learning the language only through isolated exercises.

---

## Project Goal

Build a production-quality CLI that can inspect a TLS endpoint and report:

* TLS version
* Cipher suite
* Server hostname
* Certificate chain
* Certificate subject and issuer
* Certificate validity period
* Public key and signature algorithms
* DNS/SAN names
* Hostname verification
* Certificate chain trust
* Certificate expiration status
* Days remaining until expiration

The final CLI should support both human-readable and machine-readable output.

Example:

```bash
tlscheck google.com:443
```

and:

```bash
tlscheck --json google.com:443
```

---

# Current Status

## Implemented

### 1. Go project setup

Repository/module:

```text
github.com/eshmamatovobidjon/tlscheck
```

Go version:

```text
go1.26.3
```

Current project structure:

```text
tlscheck/
├── main.go                            (entry point)
├── cli.go                             (run()/runWithArgs())
├── tls_check.go                       (checkTLS())
├── certificate.go                     (TLSResult/CertificateInfo + cert helpers)
├── verification.go                    (cert/hostname verification)
├── output.go                          (printResult()/printJSON())
├── cli_test.go
├── check_tls_test.go
├── tls_integration_test.go
├── certificate_roles_test.go
├── classify_verification_error_test.go
├── key_usages_test.go
├── extended_key_usages_test.go
├── sha256_fingerprint_test.go
├── go.mod
└── ...
```

The project has moved past a single `main.go`: responsibilities are now split across files, though everything is still `package main` — no `internal/` packages yet.

---

## 2. TCP/TLS connection

Implemented TLS connections using:

```go
tls.Dial("tcp", host, conf)
```

The application can connect to endpoints such as:

```bash
go run . google.com:443
```

The TLS connection is properly closed using:

```go
defer conn.Close()
```

---

## 3. TLS ConnectionState

Implemented extraction of TLS connection information using:

```go
state := conn.ConnectionState()
```

Currently collected:

* TLS version
* Cipher suite
* Peer certificates
* Verified certificate chains

Example:

```text
TLS Version: TLS 1.3
Cipher Suite: TLS_AES_128_GCM_SHA256
Certificates: 3
```

Go's helper functions are used to convert numeric TLS identifiers into readable names:

```go
tls.VersionName(state.Version)
tls.CipherSuiteName(state.CipherSuite)
```

---

## 4. Host and port parsing

Implemented:

```go
net.SplitHostPort(host)
```

This separates:

```text
google.com:443
```

into:

```text
hostname = google.com
port     = 443
```

The hostname is needed separately for certificate hostname verification.

Invalid input is handled with an error:

```go
return nil, fmt.Errorf("invalid host:port: %w", err)
```

---

## 5. Certificate extraction

The application reads certificates from:

```go
state.PeerCertificates
```

The first certificate is treated as the server/leaf certificate.

The application currently reports the number of certificates:

```go
CertificateCount: len(state.PeerCertificates)
```

---

## 6. Certificate information model

Created an application-level certificate DTO:

```go
type CertificateInfo struct {
    Subject            string
    Issuer             string
    ValidFrom          time.Time
    ValidUntil         time.Time
    PublicKeyAlgorithm string
    SignatureAlgorithm string
    DNSNames           []string
    Status             string
    DaysRemaining      float64
}
```

This converts the large `x509.Certificate` object into the information that TLSCheck actually wants to expose.

---

## 7. Certificate subject and issuer

Implemented:

```go
cert.Subject.String()
cert.Issuer.String()
```

Example:

```text
Subject: CN=*.google.com
Issuer: CN=WR2,O=Google Trust Services,C=US
```

---

## 8. Certificate validity period

Implemented:

```go
cert.NotBefore
cert.NotAfter
```

The result exposes:

```text
Valid From
Valid Until
```

Go's `time.Time` is used instead of manually converting timestamps.

---

## 9. Certificate expiration status

Implemented certificate status calculation:

```go
now := time.Now()

if now.Before(cert.NotBefore) {
    info.Status = "Not yet valid"
} else if now.After(cert.NotAfter) {
    info.Status = "Expired"
} else {
    info.Status = "Valid"
}
```

Possible states:

```text
Not yet valid
Valid
Expired
```

The same `now` value is used for every certificate so the entire inspection uses one consistent point in time.

---

## 10. Days remaining

Implemented:

```go
remaining := cert.NotAfter.Sub(now)
info.DaysRemaining = remaining.Hours() / 24
```

Human-readable output currently rounds the value:

```go
fmt.Printf(" Days Remaining: %.0f\n", cert.DaysRemaining)
```

JSON retains the more precise floating-point value.

---

## 11. Hostname verification

Implemented hostname verification using:

```go
cert.VerifyHostname(hostname)
```

The verification is performed against the leaf certificate:

```go
state.PeerCertificates[0]
```

This is important because intermediate and root certificates normally do not contain the server hostname in their SANs.

Example:

```text
Hostname Valid: true
```

A helper function currently wraps the standard-library operation:

```go
func verifyHostname(cert *x509.Certificate, hostname string) error {
    return cert.VerifyHostname(hostname)
}
```

---

## 12. Certificate chain trust

The TLS handshake now dials with `InsecureSkipVerify: true` so the connection always succeeds, and trust is instead determined explicitly and reported in detail:

```go
conf := &tls.Config{InsecureSkipVerify: true}

verificationErr := verifyCertificate(
    state.PeerCertificates[0],
    hostname,
    intermediates,
)
result.ChainTrusted = verificationErr == nil
```

```go
func verifyCertificate(cert *x509.Certificate, hostname string, intermediates *x509.CertPool) error {
    options := x509.VerifyOptions{
        DNSName:       hostname,
        CurrentTime:   time.Now(),
        Intermediates: intermediates,
    }

    _, err := cert.Verify(options)
    return err
}
```

When verification fails, both the raw error and a stable machine-readable reason are captured:

```go
result.VerificationError = verificationErr.Error()
result.VerificationReason = classifyVerificationError(verificationErr)
```

`classifyVerificationError` maps the standard library's error types (`x509.CertificateInvalidError`, `x509.UnknownAuthorityError`, `x509.HostnameError`) to short reason codes such as `expired`, `unknown_authority`, or `hostname_mismatch`. Hostname mismatches are reported separately via `HostnameError`.

---

## 13. Public key and signature algorithms

Implemented:

```go
cert.PublicKeyAlgorithm.String()
cert.SignatureAlgorithm.String()
```

Example:

```text
Public Key Algorithm: ECDSA
Signature Algorithm: SHA256-RSA
```

---

## 14. DNS/SAN names

Implemented:

```go
cert.DNSNames
```

These are exposed as:

```text
DNS Names
```

and in JSON:

```json
"dns_names": [
  "*.google.com",
  "google.com"
]
```

---

## 15. Human-readable output

Implemented a dedicated function:

```go
func printResult(result *TLSResult)
```

Example:

```text
TLSCheck
Checking google.com:443

TLS Connection
 Hostname: google.com
 TLS Version: TLS 1.3
 Cipher Suite: TLS_AES_128_GCM_SHA256
 Certificates: 3
 Hostname Valid: true
 Chain Trusted: true

Certificate Chain

Certificate 1
 Subject: CN=*.google.com
 Issuer: CN=WR2,O=Google Trust Services,C=US
 ...
 Status: Valid
 Days Remaining: 67
```

---

## 16. JSON output

Implemented:

```bash
go run . --json google.com:443
```

The result is serialized using:

```go
json.MarshalIndent(result, "", "  ")
```

Example:

```json
{
  "hostname": "google.com",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "certificate_count": 3,
  "hostname_valid": true,
  "chain_trusted": true,
  "certificates": []
}
```

JSON mode intentionally prints **only JSON** so the output can be piped into tools such as:

```bash
tlscheck --json google.com:443 | jq
```

---

## 17. CLI flag parsing

The standard Go `flag` package is now used.

Implemented:

```go
jsonOutput := flag.Bool("json", false, "output result as JSON")
flag.Parse()
```

Positional arguments are read with:

```go
flag.NArg()
flag.Arg(0)
```

Current usage:

```bash
tlscheck google.com:443
tlscheck --json google.com:443
```

Invalid argument counts are handled.

---

## 18. Error wrapping

The project has started using Go's error wrapping:

```go
fmt.Errorf("invalid host:port: %w", err)
```

This is an important Go error-handling pattern and will be expanded throughout the project.

---

## 19. Certificate roles (leaf / intermediate / root)

Implemented `certificateRoles()`, which labels every certificate the server sent:

```go
roles := certificateRoles(state)
```

When Go successfully builds a `VerifiedChains` path, that chain is used to assign `"leaf"`, `"intermediate"`, or `"root"` accurately. When verification fails, the leaf is still known and any remaining certificates fall back to `"intermediate"`.

---

## 20. Additional certificate metadata

`CertificateInfo` now also exposes:

```go
SerialNumber      string
IsCA              bool
KeyUsage          []string
ExtendedKeyUsage  []string
SHA256Fingerprint string
Role              string
```

`keyUsages()` decodes the `x509.KeyUsage` bitmask, `extendedKeyUsages()` maps each `x509.ExtKeyUsage` value, and `sha256Fingerprint()` hashes `cert.Raw` for a stable certificate identifier.

Still not exposed: IP/email SANs, Organization/Country, and Authority/Subject Key ID.

---

## 21. Connection timeout

Dialing now uses a bounded `net.Dialer` instead of the unbounded `tls.Dial`:

```go
dialer := &net.Dialer{Timeout: 10 * time.Second}
conn, err := tls.DialWithDialer(dialer, "tcp", host, conf)
```

The timeout is currently a fixed constant; a `--timeout` flag is still planned.

---

## 22. Proper CLI exit codes

`main()` now propagates failures with a non-zero exit status:

```go
func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, "Error:", err)
        os.Exit(1)
    }
}
```

CLI parsing also moved to an explicit `flag.NewFlagSet("tlscheck", flag.ContinueOnError)` in `runWithArgs()`, which is easier to unit test than the package-level `flag` functions.

---

## 23. Automated testing

The project now has a real test suite (`go test ./...`):

* Table-driven unit tests for `classifyVerificationError`, `keyUsages`, `extendedKeyUsages`, `sha256Fingerprint`, and `certificateRoles`.
* `cli_test.go` covers `runWithArgs()` argument validation (missing host, invalid address, unknown flag).
* `check_tls_test.go` spins up a local `tls.Listen` server with a generated self-signed certificate and runs `checkTLS()` against it end-to-end, without any network dependency.
* `tls_integration_test.go` runs `checkTLS()` against a real public host (`google.com:443`) and is skipped under `go test -short`.

---

# Current Architecture

The current application flow is:

```text
                 CLI arguments
                       │
                       ▼
                    main()
                       │
                       ▼
                 checkTLS(host)
                       │
                       ▼
              tls.Dial("tcp", ...)
                       │
                       ▼
              ConnectionState()
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
   TLS information           Certificates
          │                         │
          │                 x509.Certificate
          │                         │
          └────────────┬────────────┘
                       ▼
                  TLSResult
                       │
              ┌────────┴────────┐
              ▼                 ▼
       printResult()       printJSON()
              │                 │
              ▼                 ▼
        Human output        JSON output
```

The important architectural decision is that TLS inspection produces a `TLSResult`, and the output layer consumes that result.

This avoids duplicating TLS inspection logic for human and JSON output.

---

# Current Data Models

## TLSResult

```go
type TLSResult struct {
    Hostname           string
    TLSVersion         string
    CipherSuite        string
    CertificateCount   int
    HostnameValid      bool
    ChainTrusted       bool
    VerificationError  string
    VerificationReason string
    HostnameError      string
    Certificates       []CertificateInfo
}
```

## CertificateInfo

```go
type CertificateInfo struct {
    Subject            string
    Issuer             string
    SerialNumber       string
    ValidFrom          time.Time
    ValidUntil         time.Time
    IsCA               bool
    PublicKeyAlgorithm string
    SignatureAlgorithm string
    DNSNames           []string
    Status             string
    DaysRemaining      float64
    KeyUsage           []string
    ExtendedKeyUsage   []string
    SHA256Fingerprint  string
    Role               string
}
```

---

# Go Concepts Learned So Far

The project has already introduced several important Go concepts.

## Packages

Examples:

```go
import (
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "net"
    "time"
)
```

---

## Structs

Example:

```go
type TLSResult struct {
    Hostname string
}
```

Comparable concept in Java:

```java
class TLSResult {
    String hostname;
}
```

---

## Pointers

Example:

```go
func checkTLS(host string) (*TLSResult, error)
```

The function returns a pointer to a `TLSResult`.

---

## Multiple return values

Go functions commonly return:

```go
result, err := checkTLS(host)
```

instead of Java-style exceptions.

---

## Error handling

Current pattern:

```go
result, err := checkTLS(host)

if err != nil {
    ...
}
```

---

## `defer`

Used for resource cleanup:

```go
defer conn.Close()
```

---

## Slices

Used for certificates:

```go
[]CertificateInfo
```

and:

```go
append(result.Certificates, info)
```

---

## `time.Time`

Used for certificate dates:

```go
time.Time
```

with operations such as:

```go
now.Before(...)
now.After(...)
cert.NotAfter.Sub(now)
```

---

## Struct tags

JSON mapping:

```go
Hostname string `json:"hostname"`
```

---

## JSON serialization

Using:

```go
encoding/json
```

and:

```go
json.MarshalIndent(...)
```

---

## CLI flags

Using:

```go
flag
```

instead of manually parsing `os.Args`.

---

# Next Implementation Steps

The following work remains.

---

## Step 1 — Proper CLI exit codes

### Status

**Done**

`main()` now checks the error returned by `run()` and calls `os.Exit(1)`; see item 22 above.

---

## Step 2 — Improve certificate verification

### Status

**Done**

`verifyCertificate()` now calls `cert.Verify(x509.VerifyOptions{...})` explicitly with `DNSName`, `CurrentTime`, and `Intermediates`; see item 12 above.

---

## Step 3 — Separate certificate validation results

### Status

**Partially done**

`TLSResult` now reports `HostnameError`, `VerificationError`, and `VerificationReason` as separate fields instead of a single boolean. Still missing: a per-check breakdown (key usage validity, extended usage validity) rather than one combined verification reason.

Potential checks still to add:

```text
Key Usage:       valid
Extended Usage:  valid
```

---

## Step 4 — Better certificate-chain representation

### Status

**Done**

`certificateRoles()` labels each peer certificate as `"leaf"`, `"intermediate"`, or `"root"`, using the verified chain when available; see item 19 above.

---

## Step 5 — Add more certificate information

### Status

**Partially done**

Added: Serial number, IsCA, KeyUsage, ExtKeyUsage, SHA-256 fingerprint (see item 20 above).

Still missing:

* IPAddresses
* EmailAddresses
* Organization
* Country
* Authority Key ID
* Subject Key ID

Only add fields that are useful to TLSCheck rather than exposing the entire `x509.Certificate`.

## Step 6 — Improve hostname handling

### Status

**Planned**

Current input requires:

```bash
tlscheck google.com:443
```

Potential improvements:

```bash
tlscheck google.com
```

with default port:

```text
443
```

Also consider:

```bash
tlscheck 192.168.1.10:443
```

and IPv6:

```bash
tlscheck [::1]:443
```

Hostname verification needs special handling for IP addresses because `VerifyHostname` treats DNS names and IP SANs differently.

---

## Step 7 — Connection timeout

### Status

**Done**

`checkTLS()` now dials with `net.Dialer{Timeout: 10 * time.Second}` and `tls.DialWithDialer(...)`; see item 21 above. A configurable `--timeout` flag is still planned.

Potential CLI option:

```bash
tlscheck --timeout 5s google.com:443
```

---

## Step 8 — Context support

### Status

**Planned**

Eventually use:

```go
context.Context
```

for cancellation and deadlines.

Potential direction:

```text
CLI
 │
 ▼
context.WithTimeout(...)
 │
 ▼
TLS checker
 │
 ▼
network operation
```

This will be an important Go-specific concept for production backend development.

---

## Step 9 — Testing

### Status

**Done (unit + integration), more coverage possible**

Implemented with Go's standard `testing` package; see item 23 above. Current unit tests cover: `classifyVerificationError`, `keyUsages`, `extendedKeyUsages`, `sha256Fingerprint`, `certificateRoles`, and CLI argument validation. A local self-signed TLS server backs an end-to-end `checkTLS()` test, and a `-short`-skippable integration test hits a real host.

Still worth adding: tests for `certificateInfo()` status/day-remaining calculation and `printJSON()` serialization.

---

## Step 10 — Refactor into packages

### Status

**Partially done**

`main.go` has been split into `cli.go`, `tls_check.go`, `certificate.go`, `verification.go`, and `output.go`, each with one responsibility — but all of them remain `package main`. Moving to `internal/` sub-packages is still planned.

Once the TLS functionality is stable, move away from one large `main.go`.

Target architecture:

```text
tlscheck/
├── cmd/
│   └── tlscheck/
│       └── main.go
│
├── internal/
│   ├── checker/
│   │   ├── checker.go
│   │   └── checker_test.go
│   │
│   ├── cert/
│   │   ├── certificate.go
│   │   └── certificate_test.go
│   │
│   └── output/
│       ├── text.go
│       ├── json.go
│       └── ...
│
├── go.mod
├── README.md
├── PROJECT.md
└── LEARNING_LOG.md
```

The refactoring will be used to learn:

* package design
* exported vs unexported identifiers
* dependency direction
* interfaces
* testable architecture

---

## Step 11 — Introduce interfaces where useful

### Status

**Planned**

Interfaces should only be introduced when they solve an actual problem.

Possible areas:

* Checker
* Output
* Certificate verifier
* Network connection

For example, testing may eventually benefit from abstracting network operations.

The project should avoid creating interfaces simply because Go supports them.

---

## Step 12 — Better CLI design

### Status

**Planned**

Potential final CLI:

```bash
tlscheck google.com:443
tlscheck --json google.com:443
tlscheck --verbose google.com:443
tlscheck --timeout 5s google.com:443
```

Potential help:

```text
TLSCheck - TLS connection and certificate inspection tool

Usage:
  tlscheck [options] <host:port>

Options:
  --json       Output JSON
  --verbose    Show detailed information
  --timeout    Connection timeout

Examples:
  tlscheck google.com:443
  tlscheck --json google.com:443
```

---

## Step 13 — Structured errors

### Status

**Planned**

Move toward errors that can be categorized.

Potential categories:

* invalid input
* connection failure
* TLS handshake failure
* certificate failure
* hostname verification failure
* certificate trust failure
* timeout

This will allow the CLI to produce useful error messages and appropriate exit codes.

---

## Step 14 — JSON schema / stable output

### Status

**Planned**

The JSON format should eventually be treated as an API contract.

For example:

```json
{
  "hostname": "google.com",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "hostname_valid": true,
  "chain_trusted": true,
  "certificates": []
}
```

Future changes should avoid unnecessarily breaking scripts consuming:

```bash
tlscheck --json ...
```

---

## Step 15 — Concurrency

### Status

**Planned later**

Once the single-host implementation is solid, support multiple targets.

Example:

```bash
tlscheck google.com:443 github.com:443 amazon.com:443
```

Potential implementation:

```text
Target 1 ── goroutine ── TLS check
Target 2 ── goroutine ── TLS check
Target 3 ── goroutine ── TLS check
        │
        ▼
     Results
```

This will be used to learn:

* goroutines
* channels
* synchronization
* concurrent error handling
* worker pools
* bounded concurrency

This should come after the single-target architecture is stable.

---

## Step 16 — Docker

### Status

**Planned**

Create a minimal Docker image.

Potential usage:

```bash
docker run tlscheck google.com:443
```

Concepts:

* multi-stage builds
* static Go binaries
* minimal runtime images
* container networking
* non-root execution

---

## Step 17 — GitHub Actions CI

### Status

**Planned**

CI should eventually run:

```bash
go test ./...
go vet ./...
go build ./...
```

Potential workflow:

```text
Push / Pull Request
        │
        ▼
  GitHub Actions
        │
   ┌────┼────┐
   ▼    ▼    ▼
 test  vet  build
```

Later potentially:

* Docker build
* Release binary
* GitHub Release

---

## Step 18 — Documentation

### Status

**Planned**

Create:

```text
README.md
```

containing:

* project purpose
* installation
* usage
* examples
* JSON output
* supported options
* development instructions
* architecture
* limitations

`PROJECT.md` is the development roadmap and learning checkpoint.

`README.md` should be the user-facing documentation.

---

## Step 19 — Release binaries

### Status

**Planned**

Eventually build binaries for:

* macOS ARM64
* macOS AMD64
* Linux ARM64
* Linux AMD64
* Windows AMD64

Potentially automate releases with GitHub Actions.

---

# Learning Roadmap

The project should intentionally teach Go in roughly this order:

```text
1. Basic Go syntax
   ↓
2. Structs
   ↓
3. Pointers
   ↓
4. Multiple return values
   ↓
5. Error handling
   ↓
6. Slices
   ↓
7. Standard library
   ↓
8. CLI flags
   ↓
9. JSON
   ↓
10. time.Time
    ↓
11. Interfaces
    ↓
12. Testing
    ↓
13. Packages
    ↓
14. Context
    ↓
15. Goroutines
    ↓
16. Channels
    ↓
17. Concurrency patterns
    ↓
18. Production architecture
    ↓
19. Docker
    ↓
20. CI/CD
```

The TLS domain is the practical context through which these Go concepts are learned.

---

# Important Technical Decisions

## Keep main.go simple for now

Do not prematurely create many packages.

First understand:

```text
TLS connection
      ↓
Certificate extraction
      ↓
Verification
      ↓
TLSResult
      ↓
Output
```

Then refactor.

## Use the standard library

Prefer Go's standard library wherever possible:

* `crypto/tls`
* `crypto/x509`
* `encoding/json`
* `flag`
* `fmt`
* `net`
* `time`
* `testing`
* `context`

Avoid adding third-party dependencies unless there is a clear reason.

## Separate inspection from presentation

TLS inspection should produce structured data:

```go
TLSResult
```

Output functions should decide how that data is presented:

```go
printResult()
printJSON()
```

The TLS checker should not contain terminal formatting logic.

---

# Current Known Limitations

* Only one target is supported.
* The target currently needs `host:port` (no default port, no IP/IPv6 shorthand).
* No configurable timeout (fixed at 10s).
* Certificate validation is reported per-check (`HostnameValid`, `ChainTrusted`, `VerificationReason`) but not broken down by key usage/extended usage.
* Still `package main` — not yet split into `internal/` packages.
* No Docker image.
* No CI pipeline.
* No release automation.
* JSON schema is not yet considered a stable public contract.

---

# Current Milestone

## Milestone 1 — Basic TLS Inspector

**Status:** Complete

Implemented:

* Go module
* CLI argument parsing
* TLS connection
* TLS version
* Cipher suite
* Certificate extraction
* Certificate count
* Subject
* Issuer
* Validity dates
* Certificate status
* Days remaining
* Public key algorithm
* Signature algorithm
* DNS names
* Hostname verification
* Basic chain trust detection
* Human-readable output
* JSON output
* JSON struct tags
* flag package
* Basic error handling

Next:

* Configurable timeout flag
* Default port / IP handling
* Context cancellation
* Move to `internal/` packages

## Milestone 2 — Reliable TLS Analyzer

* Explicit certificate verification — **done**
* Detailed validation errors (`VerificationReason`, `HostnameError`) — **done**
* Connection timeout — **done** (fixed 10s; configurable flag still planned)
* Unit tests — **done**
* Integration tests — **done** (local TLS server + real host)
* Hostname/IP handling — planned
* Context cancellation — planned
* More certificate metadata (IP/email SANs, Organization, Country, key IDs) — planned

## Milestone 3 — Production CLI

* Package structure
* CLI improvements
* Stable JSON model
* Verbose mode
* Multiple targets
* Concurrency
* Bounded worker pool
* Better logging/errors

## Milestone 4 — Production Engineering

* Docker
* GitHub Actions
* `go test`
* `go vet`
* Build matrix
* Release binaries
* GitHub Releases
* Documentation
* Versioning

---

# Development Rule

For each new feature:

1. Understand the Go concept first.
2. Understand the TLS/security concept involved.
3. Implement the smallest version.
4. Test it manually.
5. Write automated tests where appropriate.
6. Refactor only after the behavior is understood.
7. Update this `PROJECT.md`.
8. Commit the milestone to Git.

The goal is not just to finish TLSCheck.

The goal is to become comfortable writing production-quality Go by building TLSCheck from the standard library upward.
