package main

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/pepa65/verifall/pinentry"
)

// Mock objects for testing
type mockSigner struct {
	returnError bool
}

func (m *mockSigner) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	if m.returnError {
		return nil, nil, nil, fmt.Errorf("mock error")
	}
	return []byte("mock_key_handle"), big.NewInt(123), big.NewInt(456), nil
}

func (m *mockSigner) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	if m.returnError {
		return nil, fmt.Errorf("mock error")
	}
	return []byte("mock_signature"), nil
}

func (m *mockSigner) Counter() uint32 {
	return 42
}

// TestFingerprintAuthentication tests that fingerprint authentication is required
func TestFingerprintAuthentication(t *testing.T) {
	// This is a unit test, not an integration test
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a server with a mock signer
	s := &server{
		pe:                 pinentry.New(),
		signer:             &mockSigner{},
		useFingerprintAuth: true,
	}

	// Test case: Fingerprint fails
	s.fingerprintAuthSucceeded = false

	// Check if final authorization is rejected
	if s.isFullyAuthenticated() {
		t.Error("Authentication should fail when fingerprint verification fails")
	}

	// Test case: Fingerprint succeeds
	s.fingerprintAuthSucceeded = true

	// Check if final authorization is approved
	if !s.isFullyAuthenticated() {
		t.Error("Authentication should succeed when fingerprint verification passes")
	}
}
