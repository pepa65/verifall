package validate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

var (
	safeAppIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\.\-\:\/\_]+$`)
)

// KeyHandle validates a key handle
func KeyHandle(handle []byte) error {
	if len(handle) == 0 {
		return fmt.Errorf("empty key handle")
	}
	
	if len(handle) > 1024 {
		return fmt.Errorf("key handle too large")
	}
	
	return nil
}

// ApplicationParameter validates an application parameter
func ApplicationParameter(param []byte) error {
	if len(param) != 32 {
		return fmt.Errorf("application parameter must be 32 bytes")
	}
	
	return nil
}

// Challenge validates a challenge
func Challenge(challenge []byte) error {
	if len(challenge) != 32 {
		return fmt.Errorf("challenge must be 32 bytes")
	}
	
	// Prevent all-zero challenges (entropy check)
	if bytes.Equal(challenge, make([]byte, 32)) {
		return fmt.Errorf("challenge cannot be all zeros")
	}
	
	return nil
}

// AppID validates an app ID string
func AppID(appID string) error {
	if !safeAppIDPattern.MatchString(appID) {
		return fmt.Errorf("app ID contains invalid characters")
	}
	
	return nil
}

// ComputeKeyHash returns a hash of the key handle
func ComputeKeyHash(keyHandle []byte) string {
	h := sha256.Sum256(keyHandle)
	return hex.EncodeToString(h[:])
}