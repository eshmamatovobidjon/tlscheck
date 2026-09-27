package main

import (
	"strings"
	"testing"
)

func TestRunWithArgsMissingHost(t *testing.T) {
	err := runWithArgs([]string{})

	if err == nil {
		t.Fatal("runWithArgs() expected an error, got nil")
	}

	if !strings.Contains(err.Error(), "usage") {
		t.Errorf("runWithArgs() error = %q, want usage message", err)
	}
}

func TestRunWithArgsInvalidAddress(t *testing.T) {
	err := runWithArgs([]string{"google.com"})

	if err == nil {
		t.Fatal("runWithArgs() expected an error, got nil")
	}

	if !strings.Contains(err.Error(), "invalid address") {
		t.Errorf("runWithArgs() error = %q, want invalid address", err)
	}
}

func TestRunWithArgsUnknownFlag(t *testing.T) {
	err := runWithArgs([]string{"--unknown", "google.com:443"})

	if err == nil {
		t.Fatal("runWithArgs() expected an error, got nil")
	}
}
