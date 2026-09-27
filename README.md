# TLSCheck

A small command-line tool that connects to a host over TLS and reports what it finds: TLS version, cipher suite, and details about every certificate in the chain (subject, issuer, validity dates, key usage, SHA-256 fingerprint, and whether the chain is trusted).

Built as a hands-on project to learn Go using a real-world tool instead of isolated exercises. See [PROJECT.md](PROJECT.md) for the development log and roadmap.

## Install

```bash
go install github.com/eshmamatovobidjon/tlscheck@latest
```

Or run it directly from a clone:

```bash
git clone https://github.com/eshmamatovobidjon/tlscheck.git
cd tlscheck
go build -o tlscheck .
```

## Usage

```bash
tlscheck <host:port>
tlscheck --json <host:port>
```

### Example

```bash
$ tlscheck google.com:443
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
 Serial Number: 1234567890
 Valid From: 2026-08-01 08:00:00 +0000 UTC
 Valid Until: 2026-10-24 08:00:00 +0000 UTC
 Is CA: false
 Public Key Algorithm: ECDSA
 Signature Algorithm: SHA256-RSA
 DNS Names: [*.google.com google.com]
 Status: Valid
 Days Remaining: 27
 Key Usage: [digital_signature]
 Extended Key Usage: [server_auth]
 SHA-256 Fingerprint: 3b8f1e2c9a7d4f6e0b1c5a9d8e2f7b4c6a1d3e5f7b9c0a2d4e6f8b1c3a5d7e9f
 Role: leaf
```

Add `--json` for machine-readable output, handy for piping into `jq`:

```bash
$ tlscheck --json google.com:443 | jq '.certificates[0]'
{
  "subject": "CN=*.google.com",
  "issuer": "CN=WR2,O=Google Trust Services,C=US",
  "serial_number": "1234567890",
  "valid_from": "2026-08-01T08:00:00Z",
  "valid_until": "2026-10-24T08:00:00Z",
  "is_ca": false,
  "public_key_algorithm": "ECDSA",
  "signature_algorithm": "SHA256-RSA",
  "dns_names": ["*.google.com", "google.com"],
  "status": "Valid",
  "days_remaining": 27.3,
  "key_usage": ["digital_signature"],
  "extended_key_usage": ["server_auth"],
  "sha256_fingerprint": "3b8f1e2c9a7d4f6e0b1c5a9d8e2f7b4c6a1d3e5f7b9c0a2d4e6f8b1c3a5d7e9f",
  "role": "leaf"
}
```

Or grab just the fingerprint:

```bash
tlscheck --json google.com:443 | jq -r '.certificates[0].sha256_fingerprint'
```


### Flags

| Flag     | Description                |
|----------|----------------------------|
| `--json` | Output the result as JSON  |

Exit code is `0` on success and `1` if the connection or verification fails.

## What it checks

- TLS version and cipher suite negotiated for the connection
- Hostname verification against the leaf certificate
- Certificate chain trust, using the system's trusted roots
- Per-certificate details: subject, issuer, serial number, validity period, status (valid/expired/not yet valid), days remaining, public key and signature algorithms, DNS names, key usage, extended key usage, SHA-256 fingerprint, and its role in the chain (leaf/intermediate/root)

## Development

```bash
go build ./...
go vet ./...
go test ./...
```

Tests include unit tests (no network needed) and a couple of integration tests: one against a local, self-signed TLS server, and one against a real host (`google.com:443`), which is skipped with `go test -short`.

## License

See [LICENSE](LICENSE).
