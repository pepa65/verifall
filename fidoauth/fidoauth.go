// fidoauth implements the fido1 authentication API with FIDO2 compatibility enhancements
package fidoauth

import (
	"fmt"
	"strings"
)

const (
	CmdRegister     = 0x01
	CmdAuthenticate = 0x02
	CmdVersion      = 0x03

	CtrlCheckOnly                     AuthCtrl = 0x07 // Check if the provided key is valid
	CtrlEnforeUserPresenceAndSign     AuthCtrl = 0x03 // confirm with user then sign
	CtrlDontEnforeUserPresenceAndSign AuthCtrl = 0x08 // just sign without confirming
)

// RPIDOrigin stores the relationship between a request and its origin
// for cross-origin authentication support
type RPIDOrigin struct {
	RP     string // Relying Party ID (domain)
	Origin string // Origin URL
}

// KeyHandleInfo extends key handles with additional metadata
type KeyHandleInfo struct {
	KeyHandle []byte    // Original key handle data
	RPID      string    // Relying Party ID associated with this key
	Origins   []string  // Origins that can use this key
	Created   int64     // Creation timestamp
	AppParam  [32]byte  // Original application parameter
}

type AuthenticatorRequest struct {
	Command uint8
	Param1  uint8
	Param2  uint8
	Size    int
	Data    []byte

	Register     *AuthenticatorRegisterReq
	Authenticate *AuthenticatorAuthReq
	
	// FIDO2 compatibility extensions
	RPID        string     // The effective Relying Party ID
	OriginInfo  *RPIDOrigin // Origin information for cross-origin handling
}

type AuthenticatorRegisterReq struct {
	ChallengeParam   [32]byte
	ApplicationParam [32]byte
}

type AuthenticatorResponse struct {
	Data   []byte
	Status uint16
}

type AuthCtrl uint8

type AuthenticatorAuthReq struct {
	Ctrl             AuthCtrl
	ChallengeParam   [32]byte
	ApplicationParam [32]byte
	KeyHandle        []byte
}

// IsRegistrationRequest returns true if this is a registration request
func (req *AuthenticatorRequest) IsRegistrationRequest() bool {
	return req.Command == CmdRegister
}

// IsAuthenticationRequest returns true if this is an authentication request
func (req *AuthenticatorRequest) IsAuthenticationRequest() bool {
	return req.Command == CmdAuthenticate
}

// GetApplicationParam returns the application parameter from the request
func (req *AuthenticatorRequest) GetApplicationParam() ([32]byte, error) {
	var empty [32]byte
	
	if req.IsRegistrationRequest() && req.Register != nil {
		return req.Register.ApplicationParam, nil
	} else if req.IsAuthenticationRequest() && req.Authenticate != nil {
		return req.Authenticate.ApplicationParam, nil
	}
	
	return empty, fmt.Errorf("no application parameter available")
}

// IsOriginAllowed checks if the origin is allowed for this application parameter
// using FIDO2 RPID rules
func (req *AuthenticatorRequest) IsOriginAllowed(origin string) bool {
	if req.RPID == "" {
		return false
	}
	
	// For FIDO2 compatibility, we allow an origin if:
	// 1. The origin's effective domain matches the RPID exactly, or
	// 2. The origin's effective domain is a subdomain of the RPID
	//
	// For example, if RPID is "example.com":
	// - example.com is allowed
	// - sub.example.com is allowed
	// - example.org is NOT allowed
	
	// Extract domain from origin
	domain := origin
	if strings.HasPrefix(origin, "http") {
		parts := strings.Split(origin, "//")
		if len(parts) > 1 {
			hostParts := strings.Split(parts[1], "/")
			domain = hostParts[0]
		}
	}
	
	// Domain exactly matches RPID
	if domain == req.RPID {
		return true
	}
	
	// Origin domain is a subdomain of RPID
	if strings.HasSuffix(domain, "."+req.RPID) {
		return true
	}
	
	return false
}

func DecodeAuthenticatorRequest(raw []byte) (*AuthenticatorRequest, error) {
	if len(raw) < 7 {
		return nil, fmt.Errorf("authenticator request too short")
	}

	req := AuthenticatorRequest{
		Command: raw[1],
		Param1:  raw[2],
		Param2:  raw[3],
		Size:    (int(raw[4]) << 16) | (int(raw[5]) << 8) | int(raw[6]),
		Data:    raw[7:],
	}

	if req.Command == CmdRegister {
		var reg AuthenticatorRegisterReq
		if len(req.Data) < len(reg.ChallengeParam)+len(reg.ApplicationParam) {
			return nil, fmt.Errorf("register request incorrect size: %d", len(req.Data))
		}

		copy(reg.ChallengeParam[:], req.Data[:32])
		copy(reg.ApplicationParam[:], req.Data[32:])
		req.Register = &reg
	} else if req.Command == CmdAuthenticate {
		var auth AuthenticatorAuthReq

		if len(req.Data) < len(auth.ChallengeParam)+len(auth.ApplicationParam)+2 {
			return nil, fmt.Errorf("authenticate request too small: %d", len(req.Data))
		}

		auth.Ctrl = AuthCtrl(req.Param1)

		switch auth.Ctrl {
		case CtrlCheckOnly, CtrlEnforeUserPresenceAndSign, CtrlDontEnforeUserPresenceAndSign:
		default:
			return nil, fmt.Errorf("unknown ctrl type: %02x", auth.Ctrl)
		}

		data := req.Data
		copy(auth.ChallengeParam[:], data[:32])
		data = data[32:]

		copy(auth.ApplicationParam[:], data[:32])
		data = data[32:]

		khLen := data[0]
		data = data[1:]

		if len(data) < int(khLen) {
			return nil, fmt.Errorf("key handle len too short %d vs %d", len(data), int(khLen))
		}

		auth.KeyHandle = data[:khLen]
		req.Authenticate = &auth
	}

	return &req, nil
}

// SetRPID sets the Relying Party ID for this request
// This should be called when processing requests to enable FIDO2 compatibility
func (req *AuthenticatorRequest) SetRPID(rpid string) {
	req.RPID = rpid
}

// SetOriginInfo sets the origin information for cross-origin support
func (req *AuthenticatorRequest) SetOriginInfo(origin string) {
	if req.RPID != "" {
		req.OriginInfo = &RPIDOrigin{
			RP:     req.RPID,
			Origin: origin,
		}
	}
}
