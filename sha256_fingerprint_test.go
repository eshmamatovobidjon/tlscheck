package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestSHA256Fingerprint(t *testing.T) {
	raw := []byte("fake-certificate-bytes")
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])

	cert := &x509.Certificate{Raw: raw}
	got := sha256Fingerprint(cert)

	if got != want {
		t.Errorf("sha256Fingerprint() = %q, want %q", got, want)
	}
}
