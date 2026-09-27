package main

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestExtendedKeyUsages(t *testing.T) {
	tests := []struct {
		name   string
		usages []x509.ExtKeyUsage
		want   []string
	}{
		{
			name:   "no usages",
			usages: nil,
			want:   nil,
		},
		{
			name:   "server and client auth",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			want:   []string{"server_auth", "client_auth"},
		},
		{
			name:   "unrecognized value",
			usages: []x509.ExtKeyUsage{x509.ExtKeyUsage(999)},
			want:   []string{"unknown"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extendedKeyUsages(tt.usages)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendedKeyUsages(%v) = %v, want %v", tt.usages, got, tt.want)
			}
		})
	}
}
