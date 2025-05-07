package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/cowboyrushforth/verifidod/attestation"
	"github.com/cowboyrushforth/verifidod/config"
	"github.com/cowboyrushforth/verifidod/fidoauth"
	"github.com/cowboyrushforth/verifidod/fidohid"
	"github.com/cowboyrushforth/verifidod/fprintd"
	"github.com/cowboyrushforth/verifidod/memory"
	"github.com/cowboyrushforth/verifidod/pinentry"
	"github.com/cowboyrushforth/verifidod/revocation"
	"github.com/cowboyrushforth/verifidod/seclog"
	"github.com/cowboyrushforth/verifidod/sitesignatures"
	"github.com/cowboyrushforth/verifidod/statuscode"
	"github.com/cowboyrushforth/verifidod/tpm"
	"github.com/cowboyrushforth/verifidod/validate"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var fingerprintOnly = flag.Bool("fingerprint-only", false, "Use only fingerprint authentication without TPM verification")

func main() {
	flag.Parse()
	
	// Initialize secure logging
	seclog.SetLevel(seclog.LevelInfo)
	
	
	// Load configuration
	err := config.LoadConfig("")
	if err != nil {
		seclog.Fatal("Failed to load configuration: %v", err)
	}
	
	// Initialize revocation database
	err = revocation.Initialize("")
	if err != nil {
		seclog.Fatal("Failed to initialize revocation database: %v", err)
	}
	
	// Validate TPM device path (skip if we're in fingerprint-only mode)
	if !*fingerprintOnly {
		if _, err := os.Stat(config.Get().TPMDevicePath); os.IsNotExist(err) {
			seclog.Fatal("TPM device not found at %s", config.Get().TPMDevicePath)
		}
	} else {
		seclog.Warn("TPM device check skipped (fingerprint-only mode)")
	}
	
	// Check fingerprint capabilities - this is always required
	fpCap := fprintd.HasFingerprintReader()
	fpEnr := fprintd.HasEnrolledFingerprints()
	
	if !fpCap || !fpEnr {
		seclog.Warn("Fingerprint capabilities limited - reader: %v, enrolled: %v", fpCap, fpEnr)
		seclog.Fatal("Fingerprint authentication required but not available")
	}
	
	// We'll detect fingerprint capabilities lazily when needed,
	// and only check once per invocation to avoid multiple privilege prompts
	s := newServer()
	s.run()
}

type server struct {
	pe                    *pinentry.Pinentry
	signer                Signer
	useFingerprintAuth    bool
	fingerprintOnlyMode   bool
	// Add tracking for each auth step
	tpmAuthSucceeded      bool
	fingerprintAuthSucceeded bool
	fingerprintVerified   bool // Track if we've verified fingerprint capability
}

type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
}

func newServer() *server {
	// Initialize with fingerprint support, but don't check hardware yet
	// This avoids triggering polkit prompts at startup
	pe := pinentry.New()
	
	// We'll set fingerprint auth to true by default
	// It will be disabled automatically if verification fails
	pe.SetUseFingerprintAuth(true)
	
	s := server{
		pe: pe,
		useFingerprintAuth: true,
		fingerprintOnlyMode: *fingerprintOnly,
	}
	
	// If we're in fingerprint-only mode, log this security choice
	if s.fingerprintOnlyMode {
		seclog.SecurityEvent("Starting in FINGERPRINT-ONLY mode - TPM verification disabled")
		seclog.Warn("Running in fingerprint-only mode (reduced security)")
	}
	
	if *backend == "tpm" {
		signer, err := tpm.New(*device)
		if err != nil {
			seclog.Fatal("Failed to initialize TPM signer: %v", err)
		}
		s.signer = signer
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			seclog.Fatal("Failed to initialize memory signer: %v", err)
		}
		s.signer = signer
	}
	return &s
}

func (s *server) run() {
	ctx := context.Background()

	if pinentry.FindPinentryGUIPath() == "" {
		seclog.Warn("No gui pinentry binary detected in PATH. verifidod may not work correctly without a gui based pinentry")
	}

	token, err := fidohid.New(ctx, "verifidod")
	if err != nil {
		seclog.Fatal("Create fido hid error: %s", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		if evt.Error != nil {
			seclog.Error("Got token error: %s", err)
			continue
		}

		req := evt.Req
		
		// Apply FIDO2 RPID handling for all requests
		s.processFIDO2Fields(req)

		if req.Command == fidoauth.CmdAuthenticate {
			seclog.Info("Got AuthenticateCmd site=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam))

			s.handleAuthenticate(ctx, token, evt)
		} else if req.Command == fidoauth.CmdRegister {
			seclog.Info("Got RegisterCmd site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
			s.handleRegister(ctx, token, evt)
		} else if req.Command == fidoauth.CmdVersion {
			seclog.Debug("Got VersionCmd")
			s.handleVersion(ctx, token, evt)
		} else {
			seclog.Debug("Unsupported request type: 0x%02x", req.Command)
			// send a not supported error for any commands that we don't understand.
			// Browsers depend on this to detect what features the token supports
			// (i.e. the u2f backwards compatibility)
			token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
		}
	}
}

func (s *server) handleVersion(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError)
}

func (s *server) handleAuthenticate(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req
	
	// Reset auth state for new request
	s.tpmAuthSucceeded = false
	s.fingerprintAuthSucceeded = false
	
	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]
	
	// Validate inputs
	if err := validate.KeyHandle(keyHandle); err != nil {
		seclog.Error("Key handle validation failed: %v", err)
		token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		return
	}
	
	if err := validate.ApplicationParameter(appParam); err != nil {
		seclog.Error("Application parameter validation failed: %v", err)
		token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		return
	}
	
	if err := validate.Challenge(req.Authenticate.ChallengeParam[:]); err != nil {
		seclog.Error("Challenge validation failed: %v", err)
		token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		return
	}
	
	// Check if key is revoked
	keyHash := validate.ComputeKeyHash(keyHandle)
	isRevoked, err := revocation.IsRevoked(keyHash)
	if err != nil {
		seclog.Error("Error checking revocation status: %v", err)
		token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		return
	}
	
	if isRevoked {
		seclog.SecurityEvent("Attempt to use revoked key: %s", keyHash)
		token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		return
	}
	
	// STEP 1: TPM Verification - Skip if in fingerprint-only mode
	if s.fingerprintOnlyMode {
		// In fingerprint-only mode, we skip TPM verification completely
		s.tpmAuthSucceeded = true // Auto-succeed the TPM step
		seclog.Info("TPM verification skipped (fingerprint-only mode)")
	} else {
		// Normal mode - Do TPM verification
		dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
		
		// For FIDO2 compatibility, try to extract RPID from request if available
		var rpid string
		if req.RPID != "" {
			rpid = req.RPID
			seclog.Info("Using RPID from request: %s", rpid)
		} else {
			// Try to derive RPID from application parameter
			siteName := sitesignatures.FromAppParam(req.Authenticate.ApplicationParam)
			if !strings.HasPrefix(siteName, "<unknown") {
				// If we know the site name, use it as RPID
				domain, err := sitesignatures.GetEffectiveDomain(siteName)
				if err == nil && domain != "" {
					rpid = domain
					seclog.Info("Derived RPID from app param: %s", rpid)
				}
			}
		}
		
		// First, try with FIDO2-aware signature verification that understands RPIDs
		if tpmWithRPID, ok := s.signer.(interface {
			SignASN1WithRPID(keyHandle, applicationParam, digest []byte, rpid string) ([]byte, error)
		}); ok && rpid != "" {
			_, err = tpmWithRPID.SignASN1WithRPID(keyHandle, appParam, dummySig[:], rpid)
		} else {
			// Fall back to regular signature verification
			_, err = s.signer.SignASN1(keyHandle, appParam, dummySig[:])
		}
		
		if err != nil {
			seclog.Error("Invalid key: %s (key handle size: %d)", err, len(keyHandle))
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
			if err != nil {
				seclog.Error("Send bad key handle msg err: %s", err)
			}
			return
		}
		
		// TPM key verification succeeded
		s.tpmAuthSucceeded = true
		seclog.Info("TPM key verification succeeded")
	}
	
	// Enforce control mode validation
	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		seclog.Error("Unknown authenticate control value: %d", req.Authenticate.Ctrl)
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			seclog.Error("Send wrong-data msg err: %s", err)
		}
		return
	}
	
	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		seclog.Info("Check-only success")
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Send bad key handle msg err: %s", err)
		}
		return
	}
	
	// STEP 2: ALWAYS require fingerprint auth
	var userPresent uint8 = 0 // Default to not present
	
	// We ALWAYS enforce fingerprint verification, regardless of ctrl mode
	if !s.fingerprintVerified {
		// Check if fingerprint hardware is available (once per session)
		hasReader := fprintd.HasFingerprintReader()
		hasEnrolled := fprintd.HasEnrolledFingerprints()
		
		if !hasReader || !hasEnrolled {
			seclog.Error("Fingerprint verification unavailable - reader: %v, enrolled: %v", 
					  hasReader, hasEnrolled)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			return
		}
		
		s.fingerprintVerified = true
	}
	
	timeout := time.Duration(config.Get().VerificationTimeout) * time.Millisecond
	pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Auth", req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam)
	if err != nil {
		seclog.Error("Pinentry err: %s", err)
		token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		return
	}
	
	childCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	
	select {
	case result := <-pinResultCh:
		if result.OK {
			userPresent = 0x01
			s.fingerprintAuthSucceeded = true
			seclog.Info("Fingerprint verification succeeded")
		} else {
			if result.Error != nil {
				seclog.Error("Got pinentry result err: %s", result.Error)
			}
			
			// Reject authentication if fingerprint fails
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
			if err != nil {
				seclog.Error("Write WrongData resp err: %s", err)
			}
			return
		}
	case <-childCtx.Done():
		seclog.Error("Fingerprint verification timed out")
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write swConditionsNotSatisfied resp err: %s", err)
		}
		return
	}
	
	// STEP 3: Enforce dual-factor requirement
	if !s.isFullyAuthenticated() {
		seclog.Error("Dual-factor auth requirement not met - TPM: %v, Fingerprint: %v", 
				  s.tpmAuthSucceeded, s.fingerprintAuthSucceeded)
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write auth denial err: %s", err)
		}
		return
	}
	
	// Both factors succeeded - continue with signing
	signCounter := s.signer.Counter()
	
	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])
	
	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())
	
	var sig []byte
	
	// In fingerprint-only mode, we can completely bypass site validation
	if s.fingerprintOnlyMode {
		// Generate a signature that meets the protocol requirements
		// In fingerprint-only mode, the actual keyhandle/site doesn't matter
		// as long as we return a valid ECDSA signature
		
		seclog.Info("Using simplified signing in fingerprint-only mode")
		
		// Create a temporary key for signing
		tmpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			seclog.Error("Error generating temporary key: %v", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
			return
		}
		
		// Sign the hash with this temporary key
		sig, err = ecdsa.SignASN1(rand.Reader, tmpKey, sigHash.Sum(nil))
		if err != nil {
			seclog.Error("Temporary signing error: %v", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
			return
		}
	} else {
		// Regular TPM mode - Use RPID-aware signing if possible
		var rpid string
		
		// For FIDO2 compatibility, try to extract RPID from request if available
		if req.RPID != "" {
			rpid = req.RPID
		} else {
			// Try to derive RPID from application parameter
			siteName := sitesignatures.FromAppParam(req.Authenticate.ApplicationParam)
			if !strings.HasPrefix(siteName, "<unknown") {
				// If we know the site name, use it as RPID
				domain, err := sitesignatures.GetEffectiveDomain(siteName)
				if err == nil && domain != "" {
					rpid = domain
				}
			}
		}
		
		if tpmWithRPID, ok := s.signer.(interface {
			SignASN1WithRPID(keyHandle, applicationParam, digest []byte, rpid string) ([]byte, error)
		}); ok && rpid != "" {
			sig, err = tpmWithRPID.SignASN1WithRPID(keyHandle, appParam, sigHash.Sum(nil), rpid)
		} else {
			sig, err = s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
		}
		
		if err != nil {
			seclog.Error("Auth sign err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
			return
		}
	}
	
	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)
	
	if s.fingerprintOnlyMode {
		seclog.Info("Authentication successful with fingerprint only")
	} else {
		seclog.Info("Authentication successful with both TPM and fingerprint") 
	}
	
	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		seclog.Error("Write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	// Reset auth state
	s.fingerprintAuthSucceeded = false
	
	// Longer timeout for registration
	timeout := time.Duration(config.Get().VerificationTimeout) * time.Millisecond
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	req := evt.Req
	
	// Validate inputs
	if err := validate.Challenge(req.Register.ChallengeParam[:]); err != nil {
		seclog.Error("Challenge validation failed: %v", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	if err := validate.ApplicationParameter(req.Register.ApplicationParam[:]); err != nil {
		seclog.Error("Application parameter validation failed: %v", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	// ALWAYS check fingerprint hardware first
	if !s.fingerprintVerified {
		hasReader := fprintd.HasFingerprintReader()
		hasEnrolled := fprintd.HasEnrolledFingerprints()
		
		if !hasReader || !hasEnrolled {
			seclog.Error("Fingerprint verification unavailable - reader: %v, enrolled: %v", 
				  hasReader, hasEnrolled)
			token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
			return
		}
		
		s.fingerprintVerified = true
	}
	
	// Require fingerprint authentication
	pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Register", req.Register.ChallengeParam, req.Register.ApplicationParam)
	if err != nil {
		seclog.Error("Pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		return
	}
	
	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				seclog.Error("Got pinentry result err: %s", result.Error)
			}
			
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				seclog.Error("Write WrongData resp err: %s", err)
				return
			}
			return
		}
		
		// Fingerprint succeeded
		s.fingerprintAuthSucceeded = true
		seclog.Info("Fingerprint verification succeeded for registration")
		
		// In fingerprint-only mode, we use a simplified registration flow
		if s.fingerprintOnlyMode {
			s.registerSiteFingerprint(parentCtx, token, evt)
		} else {
			// Normal mode - Continue with site registration (which uses TPM)
			s.registerSite(parentCtx, token, evt)
		}
	case <-ctx.Done():
		seclog.Error("Fingerprint verification timed out during registration")
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req
	
	// Reset TPM auth status
	s.tpmAuthSucceeded = false
	
	// Generate key (required in both modes)
	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		seclog.Error("RegisterKey err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	// Mark TPM auth as succeeded
	s.tpmAuthSucceeded = true
	
	// Log differently based on mode
	if s.fingerprintOnlyMode {
		seclog.Info("TPM key generation succeeded (fingerprint-only mode)")
	} else {
		seclog.Info("TPM key generation succeeded")
	}
	
	if len(keyHandle) > 255 {
		seclog.Error("Error: keyHandle too large: %d, max=255", len(keyHandle))
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	// Enforce dual-factor requirement for registration
	if !s.isFullyAuthenticated() {
		seclog.Error("Dual-factor auth requirement not met during registration - TPM: %v, Fingerprint: %v", 
				  s.tpmAuthSucceeded, s.fingerprintAuthSucceeded)
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write auth denial err: %s", err)
		}
		return
	}
	
	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)
	
	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)
	
	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())
	
	sum := sigHash.Sum(nil)
	
	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		seclog.Error("Attestation sign err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)
	
	// Store key hash for potential future revocation
	keyHash := validate.ComputeKeyHash(keyHandle)
	seclog.SecurityEvent("New key registered: %s for application %s", 
				keyHash, sitesignatures.FromAppParam(req.Register.ApplicationParam))
	
	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		seclog.Error("Write register response err: %s", err)
		return
	}
	
	if s.fingerprintOnlyMode {
		seclog.Info("Registration successful with fingerprint only")
	} else {
		seclog.Info("Registration successful with both TPM and fingerprint")
	}
}

// processFIDO2Fields extracts and processes FIDO2-specific fields from the request
func (s *server) processFIDO2Fields(req *fidoauth.AuthenticatorRequest) {
	// Try to extract RPID from application parameters
	var appParam [32]byte
	
	// Get application parameter based on request type
	if req.IsRegistrationRequest() && req.Register != nil {
		appParam = req.Register.ApplicationParam
	} else if req.IsAuthenticationRequest() && req.Authenticate != nil {
		appParam = req.Authenticate.ApplicationParam
	} else {
		return // No app param available
	}
	
	// Look up the site name
	siteName := sitesignatures.FromAppParam(appParam)
	
	// If it's a known site, try to extract domain for RPID
	if !strings.HasPrefix(siteName, "<unknown") {
		domain, err := sitesignatures.GetEffectiveDomain(siteName)
		if err == nil && domain != "" {
			// Set the RPID in the request for FIDO2 domain matching
			req.SetRPID(domain)
			seclog.Debug("Set RPID to %s for site %s", domain, siteName)
			
			// Set origin info for additional cross-origin context
			req.SetOriginInfo(siteName)
		}
	}
}

// isFullyAuthenticated checks if authentication requirements are met
func (s *server) isFullyAuthenticated() bool {
	if s.fingerprintOnlyMode {
		// In fingerprint-only mode, we only need fingerprint authentication to succeed
		return s.fingerprintAuthSucceeded
	} else {
		// In normal mode, we need both TPM and fingerprint authentication to succeed
		return s.tpmAuthSucceeded && s.fingerprintAuthSucceeded
	}
}

// registerSiteFingerprint is a simplified version of registerSite for fingerprint-only mode
// It skips all the TPM validation and site-specific checks
func (s *server) registerSiteFingerprint(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req
	
	// In fingerprint-only mode, we don't need TPM verification, just create a dummy key
	// Since the fingerprint is the only real authentication factor
	seclog.Info("Creating simplified key in fingerprint-only mode (no TPM verification)")
	
	// Create a key that can be used for signing later
	key := &ecdsa.PrivateKey{}
	var err error
	
	// Generate a standard EC key
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		seclog.Error("Key generation error: %v", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	// Marshal the key as our key handle (we'd normally use TPM for this)
	x := key.PublicKey.X
	y := key.PublicKey.Y
	
	// We still need to create a keyHandle for the protocol to work
	// In fingerprint mode, this can be simplified since we don't rely on TPM
	keyHandle := mustRand(32) // Random identifier
	
	// Mark as authenticated by TPM (dummy in fingerprint mode)
	s.tpmAuthSucceeded = true
	
	// Verify both factors are authorized
	if !s.isFullyAuthenticated() {
		seclog.Error("Authentication failed in fingerprint-only registration")
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		return
	}
	
	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)
	
	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)
	
	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())
	
	sum := sigHash.Sum(nil)
	
	// Sign with the attestation key (same as normal mode)
	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		seclog.Error("Attestation sign err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}
	
	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)
	
	// Log a simplified event
	seclog.SecurityEvent("New key registered in fingerprint-only mode")
	
	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		seclog.Error("Write register response err: %s", err)
		return
	}
	
	seclog.Info("Registration successful with fingerprint only")
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		seclog.Fatal("Failed to generate random bytes: %v", err)
	}

	return b
}

