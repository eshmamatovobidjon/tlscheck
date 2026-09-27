package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	fmt.Println("TLSCheck")

	if len(os.Args) != 2 {
		fmt.Println("Usage: tlscheck <host:port>")
	} else {
		host := os.Args[1]
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			fmt.Println("Invalid host:port:", err)
			return
		}
		fmt.Println("Checking " + host + "\n")

		conf := &tls.Config{}

		conn, err := tls.Dial("tcp", host, conf)
		if err != nil {
			fmt.Println(err)
			return
		}

		defer conn.Close()

		state := conn.ConnectionState()
		version := state.Version
		cipherSuite := state.CipherSuite
		serverName := state.ServerName
		certificates := state.PeerCertificates

		fmt.Println("TLS Connection")
		fmt.Printf(" Version: %s\n", tls.VersionName(version))
		fmt.Printf(" ServerName: %s\n", serverName)
		fmt.Printf(" CipherSuite: %s\n", tls.CipherSuiteName(cipherSuite))
		fmt.Printf(" Certificates: %d\n", len(certificates))

		fmt.Println("\nConnected to " + host)
		fmt.Printf("Certificate Chain\n")

		for i, cert := range certificates {
			fmt.Printf("\nCertificate %d\n", i+1)

			fmt.Printf(" Subject: %s\n", cert.Subject)
			fmt.Printf(" Issuer: %s\n", cert.Issuer)
			fmt.Printf(" Valid From: %s\n", cert.NotBefore)
			fmt.Printf(" Valid Until: %s\n", cert.NotAfter)
			fmt.Printf(" Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
			fmt.Printf(" Signature Algorithm: %s\n", cert.SignatureAlgorithm)
			fmt.Printf(" DNS Names: %v\n", cert.DNSNames)

			now := time.Now()

			if now.Before(cert.NotBefore) {
				fmt.Println(" Status: Not yet valid")
			} else if now.After(cert.NotAfter) {
				fmt.Println(" Status: Expired")
			} else {
				fmt.Println(" Status: Valid")
			}

			fmt.Printf(" Days Remaining: %.0f\n",
				time.Until(cert.NotAfter).Hours()/24)
		}

		certificate := certificates[0]

		if err := certificate.VerifyHostname(hostname); err != nil {
			fmt.Println("Hostname: MISMATCH")
			fmt.Println("Hostname Error:", err)
		} else {
			fmt.Println("Hostname: MATCH")
		}

		fmt.Println("\nVerified Certificate Chains")

		for i, chain := range state.VerifiedChains {
			fmt.Printf("\nVerified Chain %d\n", i+1)

			for j, cert := range chain {
				fmt.Printf("\nCertificate %d\n", j+1)
				fmt.Printf(" Subject: %s\n", cert.Subject)
				fmt.Printf(" Issuer: %s\n", cert.Issuer)
				fmt.Printf(" IS CA: %t\n", cert.IsCA)
			}
		}
	}
}
