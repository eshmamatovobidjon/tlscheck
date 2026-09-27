package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
)

type TLSResult struct {
	Hostname         string            `json:"hostname"`
	TLSVersion       string            `json:"tls_version"`
	CipherSuite      string            `json:"cipher_suite"`
	CertificateCount int               `json:"certificate_count"`
	HostnameValid    bool              `json:"hostname_valid"`
	ChainTrusted     bool              `json:"chain_trusted"`
	Certificates     []CertificateInfo `json:"certificates"`
}

type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	ValidFrom          time.Time `json:"valid_from"`
	ValidUntil         time.Time `json:"valid_until"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names"`
	Status             string    `json:"status"`
	DaysRemaining      float64   `json:"days_remaining"`
}

func main() {
	fmt.Println("TLSCheck")

	if len(os.Args) != 2 {
		fmt.Println("Usage: tlscheck <host:port>")
		return
	}

	host := os.Args[1]

	fmt.Println("Checking " + host + "\n")

	result, err := checkTLS(host)
	if err != nil {
		fmt.Println(err)
		return
	}

	printResult(result)
}

func checkTLS(host string) (*TLSResult, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port: %w", err)
	}

	conf := &tls.Config{}

	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		return nil, err
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

	if err := verifyHostname(state.PeerCertificates[0], hostname); err == nil {
		result.HostnameValid = true
	}

	result.ChainTrusted = len(state.VerifiedChains) > 0

	now := time.Now()

	for _, cert := range state.PeerCertificates {
		info := CertificateInfo{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			ValidFrom:          cert.NotBefore,
			ValidUntil:         cert.NotAfter,
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			DNSNames:           cert.DNSNames,
		}

		if now.Before(cert.NotBefore) {
			info.Status = "Not yet valid"
		} else if now.After(cert.NotAfter) {
			info.Status = "Expired"
		} else {
			info.Status = "Valid"
		}

		remaining := cert.NotAfter.Sub(now)
		info.DaysRemaining = remaining.Hours() / 24
		result.Certificates = append(result.Certificates, info)
	}
	return result, nil
}

func verifyHostname(cert *x509.Certificate, hostname string) error {
	return cert.VerifyHostname(hostname)
}

func printResult(result *TLSResult) {
	fmt.Println("TLS Connection")
	fmt.Printf(" Hostname: %s\n", result.Hostname)
	fmt.Printf(" TLS Version: %s\n", result.TLSVersion)
	fmt.Printf(" Cipher Suite: %s\n", result.CipherSuite)
	fmt.Printf(" Certificates: %d\n", result.CertificateCount)
	fmt.Printf(" Hostname Valid: %t\n", result.HostnameValid)
	fmt.Printf(" Chain Trusted: %t\n", result.ChainTrusted)

	fmt.Println("\nCertificate Chain")

	for i, cert := range result.Certificates {
		fmt.Printf("\nCertificate %d\n", i+1)
		fmt.Printf(" Subject: %s\n", cert.Subject)
		fmt.Printf(" Issuer: %s\n", cert.Issuer)
		fmt.Printf(" Valid From: %s\n", cert.ValidFrom)
		fmt.Printf(" Valid Until: %s\n", cert.ValidUntil)
		fmt.Printf(" Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
		fmt.Printf(" Signature Algorithm: %s\n", cert.SignatureAlgorithm)
		fmt.Printf(" DNS Names: %v\n", cert.DNSNames)
		fmt.Printf(" Status: %s\n", cert.Status)
		fmt.Printf(" Days Remaining: %.0f\n", cert.DaysRemaining)
	}
}
