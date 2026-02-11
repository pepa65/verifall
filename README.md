# verifall v0.0.11
**FIDO Token for Linux**
* Project `verifall` is a stripped [verifidod](https://github.com/cowboyrushforth/verifidod)
  in order to not require fingerprints (nor TPM).
* Project `verifidod` was forked from [psanford/tpm-fido](https://github.com/psanford/tpm-fido) and extensively refactored to use fingerprint authentication only, removing the TPM dependency.

## Overview
Project `verifall` is a FIDO2 token implementation for Linux that secures authentication using only the generated keys.
A virtual FIDO device is created using Linux's [uhid](https://github.com/psanford/uhid) facility, making it fully compatible with standard browsers.

### Key Security Features
* **Persistent Credential Storage**: Credentials are securely stored in a JSON file
* **Key Revocation**: Revoke compromised keys manually
* **Enhanced Logging**: Detailed security event tracking
* **Secure Configuration**: Hardened defaults with security-focused settings
* **Service Hardening**: Comprehensive systemd service hardening

## Implementation Details
Project `verifall` implements a security-focused workflow that ensures proper authentication at every step:
* Registration Process
  1. User initiates FIDO registration in their browser
  2. A unique P256 key is generated and stored in the credential store
  3. Each registration creates a secure key handle with the necessary parameters
  4. The credentials are persistently stored for future authentications
  5. The registration process completes with the key handle returned to the browser
* Authentication Process
  1. User initiates FIDO authentication in their browser
  2. The key handle with the stored credentials gets verified
  3. The key is used to sign the challenge
  4. Signature is returned to the browser to complete authentication

## Status
The project has been tested with Chrome and Firefox on Linux. It implements the FIDO/U2F protocol and works with websites supporting FIDO security keys.

## Installation
Please see the [INSTALL.md](INSTALL.md) file for detailed installation and configuration instructions.

### Build Requirements
* Go 1.22 or later
* `pinentry` program (usually installed with GPG)
* Linux with systemd (if started from a systemd unit)

### Quick Build
`go build`

## Running as a Service
The binary can be run as a user systemd service. Refer to [INSTALL.md](INSTALL.md) for complete setup instructions.

```
### Enable (for future automatic start) and start the service (after installation):
systemctl --user enable --now verifall.service

### View service status:
systemctl --user status verifall.service
```

## Usage
```
Usage of verifall:
  -store string
    	Path to the credential store (defaults to ~/.config/verifall/credentials.json)
  -version
    	print version information
```

## License
This project is licensed under the MIT License. 
* Copyright (c) 2021 Peter Sanford (original author)
* Copyright (c) 2025 Scott Rushforth
* Copyright (c) 2025 github.com/pepa65
* See the [LICENSE](LICENSE) file for the full license text.
