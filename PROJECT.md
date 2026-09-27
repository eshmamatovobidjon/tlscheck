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
├── main.go
├── go.mod
└── ...
```

The project intentionally remains in a single `main.go` while the core Go and TLS concepts are being learned.

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

Currently using:

```go
result.ChainTrusted = len(state.VerifiedChains) > 0
```

`VerifiedChains` is populated when Go successfully builds a certificate verification path using its configured trust sources.

This is currently a basic trust indication.

A more explicit certificate verification implementation is planned later.

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
    Hostname         string
    TLSVersion       string
    CipherSuite      string
    CertificateCount int
    HostnameValid    bool
    ChainTrusted     bool
    Certificates     []CertificateInfo
}
```

## CertificateInfo

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

**Next**

Currently errors are handled like:

```go
if err != nil {
    fmt.Println(err)
    return
}
```

This prints the error but exits with status code `0`.

For a real CLI, failures should return a non-zero exit code.

Target behavior:

```bash
tlscheck google.com:443
echo $?
```

Successful check:

```text
0
```

Failed check:

```text
1
```

This will introduce:

```go
os.Exit(1)
```

and teach:

* process exit status
* Unix CLI conventions
* why exit codes matter in shell scripts and CI

---

## Step 2 — Improve certificate verification

### Status

**Planned**

Current trust detection is:

```go
len(state.VerifiedChains) > 0
```

We need to understand and eventually use:

```go
x509.VerifyOptions
```

Important concepts:

* Root CA trust
* Intermediate certificates
* Certificate chain construction
* System trust store
* `DNSName`
* `KeyUsages`
* `Roots`
* `Intermediates`
* `Verify()`

Target conceptual flow:

```text
Leaf certificate
      │
      ▼
Intermediates
      │
      ▼
Trusted Root CA
      │
      ▼
x509.Verify()
      │
      ▼
Verification result
```

This will make `ChainTrusted` more explicit and controllable.

---

## Step 3 — Separate certificate validation results

### Status

**Planned**

Instead of only:

```text
Hostname Valid: true
Chain Trusted: true
```

eventually report more detailed validation information.

Potential checks:

```text
Hostname:        valid
Validity:        valid
Chain:           trusted
Key Usage:       valid
Extended Usage:  valid
```

The exact model will be designed after understanding `x509.VerifyOptions`.

---

## Step 4 — Better certificate-chain representation

### Status

**Planned**

Currently all `PeerCertificates` are represented similarly.

We should distinguish:

```text
Certificate 1 → Leaf / Server
Certificate 2 → Intermediate
Certificate 3 → Root / Chain certificate
```

Potential future model:

```go
type CertificateInfo struct {
    Position string
    ...
}
```

or a separate certificate type/role.

Important: the certificates sent by the server and the chain Go actually verifies can differ because of trust-store path building and cross-signing.

This behavior has already been observed with Google's certificate chain.

---

## Step 5 — Add more certificate information

### Status

**Planned**

Potential fields:

* Serial number
* Version
* IsCA
* KeyUsage
* ExtKeyUsage
* IPAddresses
* EmailAddresses
* Organization
* Country
* Common Name
* Authority Key ID
* Subject Key ID
* Certificate fingerprint

Example fingerprint:

```text
SHA-256:
AA:BB:CC:...
```

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

**Planned**

Currently:

```go
tls.Dial(...)
```

can potentially wait for a long time.

Introduce:

```go
net.Dialer{
    Timeout: ...,
}
```

and:

```go
tls.DialWithDialer(...)
```

This will introduce useful Go concepts:

* `net.Dialer`
* timeouts
* network reliability
* later, `context.Context`

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

**Planned**

Introduce Go's standard testing framework:

```go
testing
```

First unit tests should cover:

* `net.SplitHostPort` handling
* hostname verification
* certificate status calculation
* days remaining
* JSON serialization
* argument validation

Then integration tests can test real TLS endpoints where appropriate.

Expected files:

```text
main_test.go
```

Later:

```text
internal/checker/checker_test.go
internal/cert/certificate_test.go
```

---

## Step 10 — Refactor into packages

### Status

**Planned after core functionality**

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
* The target currently needs `host:port`.
* No configurable timeout.
* Certificate trust reporting is currently based on `VerifiedChains`.
* Certificate validation details are not yet fully exposed.
* No unit/integration tests yet.
* Everything is still in `main.go`.
* No Docker image.
* No CI pipeline.
* No release automation.
* CLI exit codes are not yet implemented.
* JSON schema is not yet considered a stable public contract.

---

# Current Milestone

## Milestone 1 — Basic TLS Inspector

**Status:** Mostly complete

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

* Exit codes
* Explicit certificate verification with `x509.VerifyOptions`
* More detailed verification results
* Better chain representation
* Connection timeout

## Milestone 2 — Reliable TLS Analyzer

* Explicit certificate verification
* Detailed validation errors
* Hostname/IP handling
* Connection timeout
* Context cancellation
* Better structured errors
* More certificate metadata
* Unit tests
* Integration tests

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
