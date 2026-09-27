package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

func checkTLS(host string) (*TLSResult, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: expected host:port", host)
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		host,
		conf,
	)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}

	defer conn.Close()

	state := conn.ConnectionState()

	result := &TLSResult{
		Hostname:         hostname,
		TLSVersion:       tls.VersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		CertificateCount: len(state.PeerCertificates),
	}

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server returned no certificates")
	}

	hostnameErr := verifyHostname(
		state.PeerCertificates[0],
		hostname,
	)

	result.HostnameValid = hostnameErr == nil

	if hostnameErr != nil {
		result.HostnameError = hostnameErr.Error()
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	verificationErr := verifyCertificate(
		state.PeerCertificates[0],
		hostname,
		intermediates,
	)
	result.ChainTrusted = verificationErr == nil

	if verificationErr != nil {
		result.VerificationError = verificationErr.Error()
		result.VerificationReason = classifyVerificationError(verificationErr)
	}

	roles := certificateRoles(state)
	now := time.Now()

	for i, cert := range state.PeerCertificates {
		info := certificateInfo(cert, roles[i], now)
		result.Certificates = append(result.Certificates, info)
	}

	return result, nil
}
