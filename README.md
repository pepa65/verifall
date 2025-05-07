# VerifidoD: Fingerprint-Based FIDO Token for Linux

> **Note:** This project was forked from [psanford/tpm-fido](https://github.com/psanford/tpm-fido) and extensively refactored to use fingerprint authentication only, removing the TPM dependency.

## Overview

VerifidoD is a FIDO2/U2F token implementation for Linux that secures authentication using fingerprint verification. It creates a virtual FIDO device using Linux's [uhid](https://github.com/psanford/uhid) facility, making it fully compatible with standard browsers.

### Key Security Features

- **Biometric Authentication**: Requires fingerprint verification (something you are) for all operations
- **Persistent Credential Storage**: Credentials are securely stored in a JSON file
- **Key Revocation**: Built-in ability to revoke compromised keys
- **Enhanced Logging**: Detailed security event tracking
- **Secure Configuration**: Hardened defaults with security-focused settings
- **Service Hardening**: Comprehensive systemd service hardening

## Implementation Details

VerifidoD implements a security-focused workflow that ensures proper authentication at every step:

### Registration Process

1. User initiates FIDO registration in their browser
2. VerifidoD requires fingerprint verification via fprintd
3. A unique P256 key is generated and stored in the credential store
4. Each registration creates a secure key handle with the necessary parameters
5. The credentials are persistently stored for future authentications
6. The registration process completes with the key handle returned to the browser

### Authentication Process

1. User initiates FIDO authentication in their browser
2. VerifidoD validates the key handle with the stored credentials
3. User must provide fingerprint verification via fprintd
4. The key is used to sign the challenge after fingerprint verification succeeds
5. Signature is returned to the browser to complete authentication

## Status

VerifidoD has been tested with Chrome and Firefox on Linux. It implements the FIDO U2F protocol and works with websites supporting FIDO security keys.

## Installation

Please see the [INSTALL.md](INSTALL.md) file for detailed installation and configuration instructions.

### Build Requirements

- Go 1.22 or later
- Fingerprint reader with enrolled fingerprints
- `pinentry` program (usually installed with GPG)
- Linux with systemd and fprintd installed

### Quick Build

```shell
go build
```

## Security Considerations

Please refer to [SECURITY.md](SECURITY.md) for a comprehensive security assessment and recommendations. The implemented security fixes include:

1. ✅ Updated dependencies to latest security-patched versions
2. ✅ Hardened authentication flow requiring both factors
3. ✅ Improved thread safety and race condition handling
4. ✅ Enhanced error handling and secure logging
5. ✅ Added input validation and defense-in-depth mechanisms
6. ✅ Implemented secure configuration management
7. ✅ Added service hardening measures

## System Configuration

### Required udev Rules

You must have proper udev rules in place for VerifidoD to access your fingerprint reader and create the virtual FIDO device:

```
# /etc/udev/rules.d/70-fido.rules

# Goodix fingerprint reader WebAuthn access
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="27c6", ATTRS{idProduct}=="658c", TAG+="uaccess"

# Configure uhid permissions for fingerprint authentication
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="input", MODE="0660"
```

After adding these rules, reload the udev rules and trigger them:

```shell
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Ensure your user belongs to the appropriate groups based on your distribution:

```shell
# On most Linux systems:
sudo usermod -aG input $USER

# On some systems you might need a specific uhid group:
sudo groupadd -r uhid  # Create group if it doesn't exist
sudo usermod -aG uhid $USER
```

**Note:** You'll need to log out and back in for group changes to take effect.

## Running as a Service

VerifidoD is designed to run as a user systemd service. Refer to [INSTALL.md](INSTALL.md) for complete setup instructions.

```shell
# Enable and start the service (after installation):
systemctl --user enable verifidod.service
systemctl --user start verifidod.service

# View service status:
systemctl --user status verifidod.service
```

## License

This project is licensed under the MIT License. 

Copyright (c) 2021 Peter Sanford (original author)  
Copyright (c) 2025 Scott Rushforth

See the [LICENSE](LICENSE) file for the full license text.
