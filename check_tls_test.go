package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// startTLSTestServer spins up a TLS listener on 127.0.0.1 backed by a
// freshly generated, self-signed certificate, and returns its address
// and certificate so tests can assert against known values.
func startTLSTestServer(t *testing.T) (addr string, cert *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// checkTLS only needs a completed handshake, no application data.
			go func(c net.Conn) {
				defer c.Close()
				if tlsConn, ok := c.(*tls.Conn); ok {
					tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), cert
}

func TestCheckTLSEndToEnd(t *testing.T) {
	addr, cert := startTLSTestServer(t)

	result, err := checkTLS(addr)
	if err != nil {
		t.Fatalf("checkTLS(%q) returned error: %v", addr, err)
	}

	if !result.HostnameValid {
		t.Errorf("HostnameValid = false, want true (cert has IP SAN 127.0.0.1)")
	}

	if result.ChainTrusted {
		t.Errorf("ChainTrusted = true, want false (self-signed cert has no trusted root)")
	}

	if result.CertificateCount != 1 {
		t.Errorf("CertificateCount = %d, want 1", result.CertificateCount)
	}

	if len(result.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(result.Certificates))
	}

	got := result.Certificates[0]

	if want := sha256Fingerprint(cert); got.SHA256Fingerprint != want {
		t.Errorf("SHA256Fingerprint = %q, want %q", got.SHA256Fingerprint, want)
	}

	if got.Role != "leaf" {
		t.Errorf("Role = %q, want %q", got.Role, "leaf")
	}

	if got.Status != "Valid" {
		t.Errorf("Status = %q, want %q", got.Status, "Valid")
	}
}
