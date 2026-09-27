# TLSCheck

## Goal
Build a CLI tool for inspecting TLS connections and certificates.

## Current phase
Phase 2 — Certificate inspection

## Completed
- [x] Go module
- [x] CLI accepts host:port
- [x] Establish TLS connection
- [x] Display TLS version
- [x] Display cipher suite

## Currently learning
- tls.Conn
- x509.Certificate
- certificate chains

## Next task
Extract and display certificate information.

## Important decisions
- Standard library first
- No Cobra initially
- No third-party TLS libraries
- Tests for important functionality

## Known issues
None

## Go concepts learned
- packages
- structs
- interfaces
- errors
- defer
- goroutines
- channels

Phase 1
TCP/TLS connection
↓
ConnectionState
↓
TLS version / cipher / server name

Phase 2
x509.Certificate
↓
Subject / Issuer / SAN
↓
validity dates

Phase 3
Certificate chain
↓
leaf → intermediate → root

Phase 4
Verification
↓
hostname
expiration
trusted CA
key usage

Phase 5
CLI design
↓
tlscheck google.com:443
tlscheck example.com:443 --json
tlscheck example.com:443 --verbose

Phase 6
Better architecture
↓
cmd/
internal/
packages
tests

Phase 7
Docker + CI
↓
GitHub Actions
Docker image