package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	fmt.Println("TLSCheck")

	if len(os.Args) != 2 {
		fmt.Println("Usage: tlscheck <host:port>")
	} else {
		host := os.Args[1]
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

		certificate := state.PeerCertificates[0]

		fmt.Println("Certificate")
		fmt.Printf(" Subject: %s\n", certificate.Subject)
		fmt.Printf(" Issuer: %s\n", certificate.Issuer)
		fmt.Printf(" Valid From: %s\n", certificate.NotBefore)
		fmt.Printf(" Valid Until: %s\n", certificate.NotAfter)
		fmt.Printf(" Public Key Algorithm: %s\n", certificate.PublicKeyAlgorithm)
		fmt.Printf(" Signature Algorithm: %s\n", certificate.SignatureAlgorithm)
		fmt.Printf(" DNS Names: %v\n", certificate.DNSNames)
	}
}
