package fprintd

import (
	"errors"
	"fmt"
	"os/user"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/cowboyrushforth/verifidod/seclog"
)

const (
	fprintdService       = "net.reactivated.Fprint"
	fprintdPath          = "/net/reactivated/Fprint/Manager"
	fprintdInterface     = "net.reactivated.Fprint.Manager"
	fprintdDevInterface  = "net.reactivated.Fprint.Device"
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
	// Get current username
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("error getting current user: %w", err)
	}
	
	// Connect to the system bus
	conn, err := dbus.SystemBus()
	if err != nil {
		return false, fmt.Errorf("error connecting to system bus: %w", err)
	}
	
	// Get the device path through the manager
	var devicePath dbus.ObjectPath
	manager := conn.Object(fprintdService, dbus.ObjectPath(fprintdPath))
	call := manager.Call(fprintdInterface+".GetDefaultDevice", 0)
	if call.Err != nil {
		return false, fmt.Errorf("error getting fingerprint device: %w", call.Err)
	}
	
	err = call.Store(&devicePath)
	if err != nil {
		return false, fmt.Errorf("error storing device path: %w", err)
	}
	
	if devicePath == "" || devicePath == "/" {
		return false, errors.New("no fingerprint readers available")
	}
	
	seclog.Info("Using fingerprint device: %s", devicePath)
	
	// Get the device object
	device := conn.Object(fprintdService, devicePath)
	
	// Set up signal handler for VerifyStatus BEFORE claiming
	match := fmt.Sprintf("type='signal',interface='%s',member='VerifyStatus',path='%s'",
		fprintdDevInterface, devicePath)
	
	if err := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, match).Err; err != nil {
		return false, fmt.Errorf("error setting up signal handler: %w", err)
	}
	
	// Create a channel for signals
	signals := make(chan *dbus.Signal, 10)
	conn.Signal(signals)
	
	// Clean up signal handler when done
	defer func() {
		conn.RemoveSignal(signals)
		conn.BusObject().Call("org.freedesktop.DBus.RemoveMatch", 0, match)
	}()
	
	// Claim the device for current user - per API docs, we need user's name
	// but we use empty string to auto-determine current user
	claimCall := device.Call(fprintdDevInterface+".Claim", 0, currentUser.Username)
	if claimCall.Err != nil {
		return false, fmt.Errorf("failed to claim fingerprint device: %w", claimCall.Err)
	}
	
	// Always release the device when we're done
	defer func() {
		if err := device.Call(fprintdDevInterface+".Release", 0).Err; err != nil {
			seclog.Error("Error releasing device: %v", err)
		} else {
			seclog.Debug("Device released successfully")
		}
	}()
	
	// Start verification - use "any" finger
	if err := device.Call(fprintdDevInterface+".VerifyStart", 0, "any").Err; err != nil {
		return false, fmt.Errorf("error starting verification: %w", err)
	}
	
	seclog.Info("Fingerprint verification started for user %s", currentUser.Username)
	
	// Wait for verification to complete with timeout
	resultChan := make(chan bool)
	errorChan := make(chan error)
	
	// Process signals in a goroutine
	go func() {
		for signal := range signals {
			if signal.Name != fprintdDevInterface+".VerifyStatus" {
				continue
			}
			
			// Per docs, VerifyStatus sends (result string, done bool)
			if len(signal.Body) < 2 {
				seclog.Error("Signal body too short: %v", signal.Body)
				continue
			}
			
			// Extract status and done flag
			status, ok := signal.Body[0].(string)
			if !ok {
				seclog.Error("Status not a string: %T %v", signal.Body[0], signal.Body[0])
				continue
			}
			
			done, ok := signal.Body[1].(bool)
			if !ok {
				seclog.Error("Done flag not a bool: %T %v", signal.Body[1], signal.Body[1])
				continue
			}
			
			seclog.Debug("Got verification status: %s (done: %v)", status, done)
			
			// Only process if done is true
			if !done {
				continue
			}
			
			// Handle different status codes
			switch status {
			case verifyStatusVerify:
				// Success!
				device.Call(fprintdDevInterface+".VerifyStop", 0)
				resultChan <- true
				return
			case verifyStatusNoMatch:
				// No match
				device.Call(fprintdDevInterface+".VerifyStop", 0)
				resultChan <- false
				return
			case verifyStatusUnknown:
				// Unknown error
				device.Call(fprintdDevInterface+".VerifyStop", 0)
				errorChan <- errors.New("unknown error during fingerprint verification")
				return
			}
		}
	}()
	
	// Wait for result or error with timeout
	select {
	case result := <-resultChan:
		if result {
			seclog.SecurityEvent("Fingerprint verification succeeded")
		} else {
			seclog.Warn("Fingerprint verification failed - no match")
		}
		return result, nil
	case err := <-errorChan:
		seclog.Error("Fingerprint verification error: %v", err)
		return false, err
	case <-time.After(30 * time.Second):
		// Timeout after 30 seconds
		// Stop the verification
		device.Call(fprintdDevInterface+".VerifyStop", 0)
		seclog.Error("Fingerprint verification timed out")
		return false, errors.New("fingerprint verification timed out")
	}
}

// HasFingerprintReader checks if the system has a fingerprint reader
func HasFingerprintReader() bool {
	// Connect to system bus
	conn, err := dbus.SystemBus()
	if err != nil {
		seclog.Error("Error connecting to system bus: %v", err)
		return false
	}
	
	// Try to get a device
	var devicePath dbus.ObjectPath
	err = conn.Object(fprintdService, dbus.ObjectPath(fprintdPath)).Call(
		fprintdInterface+".GetDefaultDevice", 0).Store(&devicePath)
	if err != nil {
		seclog.Debug("No fingerprint reader found: %v", err)
		return false
	}
	
	if devicePath == "" || devicePath == "/" {
		seclog.Debug("Empty device path returned")
		return false
	}
	
	seclog.Info("Found fingerprint reader at: %v", devicePath)
	return true
}

// HasEnrolledFingerprints checks if the current user has enrolled fingerprints
func HasEnrolledFingerprints() bool {
	fingers, err := ListEnrolledFingers()
	if err != nil {
		seclog.Debug("Error listing enrolled fingerprints: %v", err)
		return false
	}
	
	if len(fingers) > 0 {
		seclog.Info("Found enrolled fingerprints: %v", fingers)
		return true
	}
	
	seclog.Debug("No enrolled fingerprints found")
	return false
}

// ListEnrolledFingers returns a list of the current user's enrolled fingerprints
func ListEnrolledFingers() ([]string, error) {
	// Get current username
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("error getting current user: %w", err)
	}
	
	// Connect to system bus
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("error connecting to system bus: %w", err)
	}
	
	// Get default device
	var devicePath dbus.ObjectPath
	err = conn.Object(fprintdService, dbus.ObjectPath(fprintdPath)).Call(
		fprintdInterface+".GetDefaultDevice", 0).Store(&devicePath)
	if err != nil {
		return nil, fmt.Errorf("error getting device: %w", err)
	}
	
	if devicePath == "" || devicePath == "/" {
		return nil, errors.New("no fingerprint reader found")
	}
	
	// ListEnrolledFingers doesn't require claiming the device first
	var fingers []string
	err = conn.Object(fprintdService, devicePath).Call(
		fprintdDevInterface+".ListEnrolledFingers", 0, currentUser.Username).Store(&fingers)
	
	if err != nil {
		return nil, fmt.Errorf("error listing enrolled fingers: %w", err)
	}
	
	return fingers, nil
}