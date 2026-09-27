package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestCertificateRolesWithoutVerifiedChain(t *testing.T) {
	leaf := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
	}

	intermediate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
	}

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			leaf,
			intermediate,
		},
	}

	got := certificateRoles(state)

	want := []string{
		"leaf",
		"intermediate",
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("certificateRoles() = %v, want %v", got, want)
	}
}

// x509.Certificate.Equal only compares Raw, so fake certs only need distinct Raw bytes.
func fakeCert(raw string) *x509.Certificate {
	return &x509.Certificate{Raw: []byte(raw)}
}

func TestCertificateRoles(t *testing.T) {
	leaf := fakeCert("leaf")
	intermediate := fakeCert("intermediate")
	root := fakeCert("root")

	tests := []struct {
		name  string
		state tls.ConnectionState
		want  []string
	}{
		{
			name:  "no certificates",
			state: tls.ConnectionState{},
			want:  []string{},
		},
		{
			name: "single leaf, no verified chain",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf},
			},
			want: []string{"leaf"},
		},
		{
			name: "leaf and intermediate, unverified falls back to intermediate",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf, intermediate},
			},
			want: []string{"leaf", "intermediate"},
		},
		{
			name: "verified chain identifies leaf, intermediate and root",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf, intermediate},
				VerifiedChains:   [][]*x509.Certificate{{leaf, intermediate, root}},
			},
			want: []string{"leaf", "intermediate"},
		},
		{
			name: "verified chain with only leaf and root",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf},
				VerifiedChains:   [][]*x509.Certificate{{leaf, root}},
			},
			want: []string{"leaf"},
		},
		{
			name: "verified chain with root included in peer certificates",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf, intermediate, root},
				VerifiedChains:   [][]*x509.Certificate{{leaf, intermediate, root}},
			},
			want: []string{"leaf", "intermediate", "root"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certificateRoles(tt.state)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("certificateRoles() = %v, want %v", got, tt.want)
			}
		})
	}
}
