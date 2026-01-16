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
	"strings"
	"time"

	"github.com/pepa65/verifall/attestation"
	"github.com/pepa65/verifall/config"
	"github.com/pepa65/verifall/fidoauth"
	"github.com/pepa65/verifall/fidohid"
	"github.com/pepa65/verifall/jsonsigner"
	"github.com/pepa65/verifall/pinentry"
	"github.com/pepa65/verifall/revocation"
	"github.com/pepa65/verifall/seclog"
	"github.com/pepa65/verifall/sitesignatures"
	"github.com/pepa65/verifall/statuscode"
	"github.com/pepa65/verifall/validate"
)

const version = "0.0.10"

var storePath = flag.String("store", "", "Path to the credential store (defaults to ~/.config/verifall/credentials.json)")
func main() {
	// Initialize secure logging
	seclog.SetLevel(seclog.LevelInfo)
	versionFlag := flag.Bool("version", false, "print version information")
	flag.Parse()
	if *versionFlag {
		seclog.Info("Version: %s", version)
		return
	}

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

	s := newServer()
	s.run()
}

type server struct {
	pe                       *pinentry.Pinentry
	signer                   Signer
	useFingerprintAuth       bool
	fingerprintAuthSucceeded bool
	fingerprintVerified      bool // Track if we've verified fingerprint capability
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
		pe:                 pe,
		useFingerprintAuth: true,
	}

	// Initialize our JSON signer for credential storage
	storePathToUse := *storePath
	if storePathToUse == "" {
		storePathToUse = config.Get().CredentialStorePath
	}

	signer, err := jsonsigner.New(storePathToUse)
	if err != nil {
		seclog.Fatal("Failed to initialize JSON credential store: %v", err)
	}
	s.signer = signer

	seclog.Info("Using JSON credential store at %s", storePathToUse)

	return &s
}

func (s *server) run() {
	ctx := context.Background()

	if pinentry.FindPinentryGUIPath() == "" {
		seclog.Warn("No gui pinentry binary detected in PATH. verifidall may not work correctly without a gui based pinentry")
	}

	token, err := fidohid.New(ctx, "verifall")
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

	// Perform pre-check - verify we can sign with this key handle
	dummySig := sha256.Sum256([]byte("verify-key-handle"))

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
	if signerWithRPID, ok := s.signer.(interface {
		SignASN1WithRPID(keyHandle, applicationParam, digest []byte, rpid string) ([]byte, error)
	}); ok && rpid != "" {
		_, err = signerWithRPID.SignASN1WithRPID(keyHandle, appParam, dummySig[:], rpid)
	} else {
		// Fall back to regular signature verification
		_, err = s.signer.SignASN1(keyHandle, appParam, dummySig[:])
	}

	if err != nil {
		seclog.Error("Invalid key handle: %s (size: %d)", err, len(keyHandle))
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			seclog.Error("Send bad key handle msg err: %s", err)
		}
		return
	}

	seclog.Info("Key handle validation succeeded")

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
		seclog.Info("Check-only request succeeded")
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Send check-only response err: %s", err)
		}
		return
	}
	// No fingerprint authentication
	var userPresent uint8 = 1 // Default to not present
	s.fingerprintVerified = true

	// Request fingerprint authentication
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
		seclog.Error("Verification timed out")
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write timeout response err: %s", err)
		}
		return
	}

	// Ensure fingerprint auth succeeded
	if !s.fingerprintAuthSucceeded {
		seclog.Error("Authentication failed")
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write auth denial err: %s", err)
		}
		return
	}

	// Fingerprint succeeded - continue with signing
	signCounter := s.signer.Counter()

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	// Sign the authentication request
	var sig []byte

	// Try RPID-aware signing if possible
	if signerWithRPID, ok := s.signer.(interface {
		SignASN1WithRPID(keyHandle, applicationParam, digest []byte, rpid string) ([]byte, error)
	}); ok && rpid != "" {
		sig, err = signerWithRPID.SignASN1WithRPID(keyHandle, appParam, sigHash.Sum(nil), rpid)
	} else {
		sig, err = s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
	}

	if err != nil {
		seclog.Error("Auth sign err: %s", err)
		token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		return
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	seclog.Info("Authentication successful")

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

	s.fingerprintVerified = true

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

		// Continue with site registration
		s.registerSite(parentCtx, token, evt)

	case <-ctx.Done():
		seclog.Error("Verification timed out during registration")
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			seclog.Error("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	// Generate key using our JSON signer
	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		seclog.Error("RegisterKey err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}

	seclog.Info("Key generation succeeded")

	if len(keyHandle) > 255 {
		seclog.Error("Error: keyHandle too large: %d, max=255", len(keyHandle))
		token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
		return
	}

	// Ensure fingerprint authentication succeeded
	if !s.fingerprintAuthSucceeded {
		seclog.Error("Authentication required for registration")
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

	seclog.Info("Registration successful")
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
	// In our system, fingerprint authentication is the only requirement
	return s.fingerprintAuthSucceeded
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		seclog.Fatal("Failed to generate random bytes: %v", err)
	}

	return b
}
