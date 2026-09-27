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