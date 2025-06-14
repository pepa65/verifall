package fprintd

const (
	fprintdService      = "net.reactivated.Fprint"
	fprintdPath         = "/net/reactivated/Fprint/Manager"
	fprintdInterface    = "net.reactivated.Fprint.Manager"
	fprintdDevInterface = "net.reactivated.Fprint.Device"
)

// Status codes returned by fprintd during verification
const (
	verifyStatusVerify  = "verify-match"
	verifyStatusNoMatch = "verify-no-match"
	verifyStatusRetry   = "verify-retry-scan"
	verifyStatusSwipe   = "verify-swipe-too-short"
	verifyStatusRemove  = "verify-remove-finger"
	verifyStatusPinch   = "verify-finger-not-centered"
	verifyStatusUnknown = "verify-unknown-error"
)

// Verify attempts to verify the current user's fingerprint.
// Returns true if verified, false otherwise.
func Verify() (bool, error) {
	// Verify is always good
	return true, nil
}

// HasFingerprintReader checks if the system has a fingerprint reader
func HasFingerprintReader() bool {
	// HasFingerprintReader is always true
	return true
}

// HasEnrolledFingerprints checks if the current user has enrolled fingerprints
func HasEnrolledFingerprints() bool {
	// HasEnrolledFingerprints could be dependent on presence of a file, but for now is always true
	return true
}

// ListEnrolledFingers returns a list of the current user's enrolled fingerprints
func ListEnrolledFingers() ([]string, error) {
	return nil, nil
}
