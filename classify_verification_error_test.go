package main

import (
	"crypto/x509"
	"errors"
	"testing"
)

func TestClassifyVerificationError(t *testing.T) {
	// table-driven test: one entry per input/expected-output pair
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "nil error",
			err:  nil,
			want: "",
		},
		{
			name: "expired certificate",
			err:  x509.CertificateInvalidError{Reason: x509.Expired},
			want: "expired",
		},
		{
			name: "not authorized to sign",
			err:  x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign},
			want: "not_authorized_to_sign",
		},
		{
			name: "incompatible usage",
			err:  x509.CertificateInvalidError{Reason: x509.IncompatibleUsage},
			want: "incompatible_usage",
		},
		{
			name: "ca not authorized for this name",
			err:  x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForThisName},
			want: "ca_not_authorized_for_this_name",
		},
		{
			name: "too many intermediates",
			err:  x509.CertificateInvalidError{Reason: x509.TooManyIntermediates},
			want: "too_many_intermediates",
		},
		{
			name: "name constraints without sans",
			err:  x509.CertificateInvalidError{Reason: x509.NameConstraintsWithoutSANs},
			want: "name_constraints_without_sans",
		},
		{
			name: "unhandled certificate invalid reason",
			err:  x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign + 100},
			want: "certificate_invalid",
		},
		{
			name: "unknown authority",
			err:  x509.UnknownAuthorityError{},
			want: "unknown_authority",
		},
		{
			name: "hostname mismatch",
			err:  x509.HostnameError{Host: "example.com"},
			want: "hostname_mismatch",
		},
		{
			name: "generic error",
			err:  errors.New("connection reset"),
			want: "verification_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyVerificationError(tt.err)
			if got != tt.want {
				t.Errorf("classifyVerificationError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
