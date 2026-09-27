package main

import "testing"

func TestCheckTLSIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	result, err := checkTLS("google.com:443")
	if err != nil {
		t.Fatalf("checkTLS() returned error: %v", err)
	}

	if !result.HostnameValid {
		t.Errorf("HostnameValid = false, want true")
	}

	if !result.ChainTrusted {
		t.Errorf("ChainTrusted = false, want true")
	}

	if result.CertificateCount == 0 {
		t.Errorf("CertificateCount = 0, want > 0")
	}
}
