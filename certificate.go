package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"
)

type TLSResult struct {
	Hostname           string            `json:"hostname"`
	TLSVersion         string            `json:"tls_version"`
	CipherSuite        string            `json:"cipher_suite"`
	CertificateCount   int               `json:"certificate_count"`
	HostnameValid      bool              `json:"hostname_valid"`
	ChainTrusted       bool              `json:"chain_trusted"`
	VerificationError  string            `json:"verification_error"`
	VerificationReason string            `json:"verification_reason"`
	HostnameError      string            `json:"hostname_error"`
	Certificates       []CertificateInfo `json:"certificates"`
}

type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	ValidFrom          time.Time `json:"valid_from"`
	ValidUntil         time.Time `json:"valid_until"`
	IsCA               bool      `json:"is_ca"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names"`
	Status             string    `json:"status"`
	DaysRemaining      float64   `json:"days_remaining"`
	KeyUsage           []string  `json:"key_usage"`
	ExtendedKeyUsage   []string  `json:"extended_key_usage"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
	Role               string    `json:"role"`
}

func certificateInfo(cert *x509.Certificate, role string, now time.Time) CertificateInfo {
	info := CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		ValidFrom:          cert.NotBefore,
		ValidUntil:         cert.NotAfter,
		IsCA:               cert.IsCA,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		KeyUsage:           keyUsages(cert.KeyUsage),
		ExtendedKeyUsage:   extendedKeyUsages(cert.ExtKeyUsage),
		SHA256Fingerprint:  sha256Fingerprint(cert),
		Role:               role,
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

	return info
}

func extendedKeyUsages(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "any",
		x509.ExtKeyUsageServerAuth:                     "server_auth",
		x509.ExtKeyUsageClientAuth:                     "client_auth",
		x509.ExtKeyUsageCodeSigning:                    "code_signing",
		x509.ExtKeyUsageEmailProtection:                "email_protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "ipsec_end_system",
		x509.ExtKeyUsageIPSECTunnel:                    "ipsec_tunnel",
		x509.ExtKeyUsageIPSECUser:                      "ipsec_user",
		x509.ExtKeyUsageTimeStamping:                   "time_stamping",
		x509.ExtKeyUsageOCSPSigning:                    "ocsp_signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoft_server_gated_crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscape_server_gated_crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoft_commercial_code_signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoft_kernel_code_signing",
	}

	var result []string
	for _, usage := range usages {
		if name, ok := names[usage]; ok {
			result = append(result, name)
		} else {
			result = append(result, "unknown")
		}
	}

	return result
}

func keyUsages(usage x509.KeyUsage) []string {
	var result []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		result = append(result, "digital_signature")
	}

	if usage&x509.KeyUsageContentCommitment != 0 {
		result = append(result, "content_commitment")
	}

	if usage&x509.KeyUsageKeyEncipherment != 0 {
		result = append(result, "key_encipherment")
	}

	if usage&x509.KeyUsageDataEncipherment != 0 {
		result = append(result, "data_encipherment")
	}

	if usage&x509.KeyUsageKeyAgreement != 0 {
		result = append(result, "key_agreement")
	}

	if usage&x509.KeyUsageCertSign != 0 {
		result = append(result, "cert_signing")
	}

	if usage&x509.KeyUsageCRLSign != 0 {
		result = append(result, "crl_signing")
	}

	if usage&x509.KeyUsageEncipherOnly != 0 {
		result = append(result, "encipher_only")
	}

	if usage&x509.KeyUsageDecipherOnly != 0 {
		result = append(result, "decipher_only")
	}

	return result
}

func sha256Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

func certificateRoles(state tls.ConnectionState) []string {
	roles := make([]string, len(state.PeerCertificates))

	if len(roles) == 0 {
		return roles
	}

	// The first certificate sent by the server is always the leaf.
	roles[0] = "leaf"

	// If Go successfully verified a chain, use the verified chain
	// to identify the root and intermediates.
	if len(state.VerifiedChains) > 0 {
		chain := state.VerifiedChains[0]

		for i, cert := range chain {
			for j, peerCert := range state.PeerCertificates {
				if cert.Equal(peerCert) {
					if i == 0 {
						roles[j] = "leaf"
					} else if i == len(chain)-1 {
						roles[j] = "root"
					} else {
						roles[j] = "intermediate"
					}
				}
			}
		}
	} else {
		// Verification failed, so we don't have a trusted root.
		// Any additional certificates supplied by the server
		// are treated as intermediates.
		for i := 1; i < len(roles); i++ {
			roles[i] = "intermediate"
		}
	}

	return roles
}
