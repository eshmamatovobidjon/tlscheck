package main

import (
	"crypto/x509"
	"errors"
	"time"
)

func verifyCertificate(cert *x509.Certificate, hostname string, intermediates *x509.CertPool) error {
	options := x509.VerifyOptions{
		DNSName:       hostname,
		CurrentTime:   time.Now(),
		Intermediates: intermediates,
	}

	_, err := cert.Verify(options)
	return err
}

func verifyHostname(cert *x509.Certificate, hostname string) error {
	return cert.VerifyHostname(hostname)
}

func classifyVerificationError(err error) string {
	if err == nil {
		return ""
	}

	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		switch certErr.Reason {
		case x509.Expired:
			return "expired"

		case x509.NotAuthorizedToSign:
			return "not_authorized_to_sign"

		case x509.IncompatibleUsage:
			return "incompatible_usage"

		case x509.CANotAuthorizedForThisName:
			return "ca_not_authorized_for_this_name"

		case x509.TooManyIntermediates:
			return "too_many_intermediates"

		case x509.NameConstraintsWithoutSANs:
			return "name_constraints_without_sans"

		default:
			return "certificate_invalid"
		}
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return "unknown_authority"
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return "hostname_mismatch"
	}

	return "verification_failed"
}
