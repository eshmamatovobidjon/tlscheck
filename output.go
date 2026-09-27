package main

import (
	"encoding/json"
	"fmt"
)

func printResult(result *TLSResult) {
	fmt.Println("TLS Connection")
	fmt.Printf(" Hostname: %s\n", result.Hostname)
	fmt.Printf(" TLS Version: %s\n", result.TLSVersion)
	fmt.Printf(" Cipher Suite: %s\n", result.CipherSuite)
	fmt.Printf(" Certificates: %d\n", result.CertificateCount)
	fmt.Printf(" Hostname Valid: %t\n", result.HostnameValid)
	fmt.Printf(" Chain Trusted: %t\n", result.ChainTrusted)

	if result.HostnameError != "" {
		fmt.Printf(" Hostname Error: %s\n", result.HostnameError)
	}

	if result.VerificationReason != "" {
		fmt.Printf(" Verification Reason: %s\n", result.VerificationReason)
	}

	if result.VerificationError != "" {
		fmt.Printf(" Verification Error: %s\n", result.VerificationError)
	}

	fmt.Println("\nCertificate Chain")

	for i, cert := range result.Certificates {
		fmt.Printf("\nCertificate %d\n", i+1)
		fmt.Printf(" Subject: %s\n", cert.Subject)
		fmt.Printf(" Issuer: %s\n", cert.Issuer)
		fmt.Printf(" Serial Number: %s\n", cert.SerialNumber)
		fmt.Printf(" Valid From: %s\n", cert.ValidFrom)
		fmt.Printf(" Valid Until: %s\n", cert.ValidUntil)
		fmt.Printf(" Is CA: %t\n", cert.IsCA)
		fmt.Printf(" Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
		fmt.Printf(" Signature Algorithm: %s\n", cert.SignatureAlgorithm)
		fmt.Printf(" DNS Names: %v\n", cert.DNSNames)
		fmt.Printf(" Status: %s\n", cert.Status)
		fmt.Printf(" Days Remaining: %.0f\n", cert.DaysRemaining)
		fmt.Printf(" Key Usage: %v\n", cert.KeyUsage)
		fmt.Printf(" Extended Key Usage: %v\n", cert.ExtendedKeyUsage)
		fmt.Printf(" SHA-256 Fingerprint: %s\n", cert.SHA256Fingerprint)
		fmt.Printf(" Role: %s\n", cert.Role)
	}
}

func printJSON(result *TLSResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
