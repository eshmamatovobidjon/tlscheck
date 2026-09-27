package main

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestKeyUsages(t *testing.T) {
	tests := []struct {
		name  string
		usage x509.KeyUsage
		want  []string
	}{
		{
			name:  "no usage",
			usage: 0,
			want:  nil,
		},
		{
			name:  "digital signature only",
			usage: x509.KeyUsageDigitalSignature,
			want:  []string{"digital_signature"},
		},
		{
			name:  "cert sign and crl sign",
			usage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			want:  []string{"cert_signing", "crl_signing"},
		},
		{
			name: "all usages",
			usage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
			want: []string{
				"digital_signature", "content_commitment", "key_encipherment",
				"data_encipherment", "key_agreement", "cert_signing",
				"crl_signing", "encipher_only", "decipher_only",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyUsages(tt.usage)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyUsages(%v) = %v, want %v", tt.usage, got, tt.want)
			}
		})
	}
}
